import sqlite3
import os
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify,
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import date

app = Flask(__name__)
app.secret_key = os.urandom(24)
DB_PATH = "usuarios.db"


# ── DB ────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                nome      TEXT    NOT NULL,
                email     TEXT    NOT NULL UNIQUE,
                senha     TEXT    NOT NULL,
                role      TEXT    NOT NULL DEFAULT 'usuario',
                ativo     INTEGER NOT NULL DEFAULT 1,
                criado_em TEXT    DEFAULT (datetime('now'))
            )
        """)
        for col, defn in [
            ("role",      "TEXT    NOT NULL DEFAULT 'usuario'"),
            ("ativo",     "INTEGER NOT NULL DEFAULT 1"),
            ("criado_em", "TEXT    DEFAULT (datetime('now'))"),
        ]:
            try:
                conn.execute(f"ALTER TABLE usuarios ADD COLUMN {col} {defn}")
            except Exception:
                pass

        conn.execute("""
            CREATE TABLE IF NOT EXISTS clientes (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id   INTEGER NOT NULL,
                nome      TEXT    NOT NULL,
                email     TEXT,
                telefone  TEXT,
                empresa   TEXT,
                status    TEXT    NOT NULL DEFAULT 'lead',
                criado_em TEXT    DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES usuarios(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS notas (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                cliente_id INTEGER NOT NULL,
                user_id    INTEGER NOT NULL,
                texto      TEXT    NOT NULL,
                criado_em  TEXT    DEFAULT (datetime('now')),
                FOREIGN KEY (cliente_id) REFERENCES clientes(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS deals (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                cliente_id INTEGER,
                titulo     TEXT    NOT NULL,
                valor      REAL    DEFAULT 0,
                etapa      TEXT    NOT NULL DEFAULT 'novo',
                ordem      INTEGER DEFAULT 0,
                criado_em  TEXT    DEFAULT (datetime('now')),
                FOREIGN KEY (user_id)   REFERENCES usuarios(id),
                FOREIGN KEY (cliente_id) REFERENCES clientes(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS transacoes (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id   INTEGER NOT NULL,
                tipo      TEXT    NOT NULL,
                descricao TEXT    NOT NULL,
                valor     REAL    NOT NULL,
                categoria TEXT,
                data      TEXT    NOT NULL,
                criado_em TEXT    DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES usuarios(id)
            )
        """)


# ── Template filter ───────────────────────────

@app.template_filter("brl")
def fmt_brl(v):
    try:
        v = float(v)
        parts = f"{abs(v):.2f}".split(".")
        intpart = "{:,}".format(int(parts[0])).replace(",", ".")
        sign = "-" if v < 0 else ""
        return f"{sign}R$ {intpart},{parts[1]}"
    except Exception:
        return "R$ 0,00"


# ── Decorators ────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Faça login para continuar.", "aviso")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("user_role") != "admin":
            flash("Acesso restrito a administradores.", "erro")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


# ── Auth ──────────────────────────────────────

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        senha = request.form["senha"]
        with get_db() as conn:
            u = conn.execute(
                "SELECT * FROM usuarios WHERE email = ?", (email,)
            ).fetchone()
        if u and check_password_hash(u["senha"], senha):
            if not u["ativo"]:
                flash("Conta desativada. Contate o administrador.", "erro")
                return render_template("login.html")
            session["user_id"]   = u["id"]
            session["user_nome"] = u["nome"]
            session["user_role"] = u["role"]
            return redirect(url_for("dashboard"))
        flash("E-mail ou senha incorretos.", "erro")
    return render_template("login.html")


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        nome  = request.form["nome"].strip()
        email = request.form["email"].strip().lower()
        senha = request.form["senha"]
        if not nome or not email or not senha:
            flash("Preencha todos os campos.", "erro")
            return render_template("cadastro.html")
        if len(senha) < 6:
            flash("A senha deve ter pelo menos 6 caracteres.", "erro")
            return render_template("cadastro.html")
        hash_ = generate_password_hash(senha)
        try:
            with get_db() as conn:
                count = conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
                role  = "admin" if count == 0 else "usuario"
                conn.execute(
                    "INSERT INTO usuarios (nome, email, senha, role) VALUES (?,?,?,?)",
                    (nome, email, hash_, role),
                )
            flash("Cadastro realizado! Faça login.", "sucesso")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Este e-mail já está cadastrado.", "erro")
    return render_template("cadastro.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Você saiu da conta.", "sucesso")
    return redirect(url_for("login"))


# ── Dashboard ─────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    uid = session["user_id"]
    with get_db() as conn:
        total_clientes = conn.execute(
            "SELECT COUNT(*) FROM clientes WHERE user_id=?", (uid,)
        ).fetchone()[0]
        total_deals = conn.execute(
            "SELECT COUNT(*) FROM deals WHERE user_id=?", (uid,)
        ).fetchone()[0]
        receita_mes = conn.execute(
            """SELECT COALESCE(SUM(valor),0) FROM transacoes
               WHERE user_id=? AND tipo='receita'
               AND strftime('%Y-%m', data) = strftime('%Y-%m','now')""",
            (uid,),
        ).fetchone()[0]
        despesa_mes = conn.execute(
            """SELECT COALESCE(SUM(valor),0) FROM transacoes
               WHERE user_id=? AND tipo='despesa'
               AND strftime('%Y-%m', data) = strftime('%Y-%m','now')""",
            (uid,),
        ).fetchone()[0]
        ult_clientes = conn.execute(
            "SELECT * FROM clientes WHERE user_id=? ORDER BY id DESC LIMIT 5", (uid,)
        ).fetchall()
        ult_transacoes = conn.execute(
            "SELECT * FROM transacoes WHERE user_id=? ORDER BY id DESC LIMIT 5", (uid,)
        ).fetchall()
        deals_etapa = {
            r["etapa"]: r["total"]
            for r in conn.execute(
                "SELECT etapa, COUNT(*) as total FROM deals WHERE user_id=? GROUP BY etapa",
                (uid,),
            ).fetchall()
        }
    return render_template(
        "dashboard.html",
        total_clientes=total_clientes,
        total_deals=total_deals,
        receita_mes=receita_mes,
        despesa_mes=despesa_mes,
        saldo_mes=receita_mes - despesa_mes,
        ult_clientes=ult_clientes,
        ult_transacoes=ult_transacoes,
        deals_etapa=deals_etapa,
    )


# ── CRM ───────────────────────────────────────

@app.route("/crm")
@login_required
def crm():
    uid    = session["user_id"]
    status = request.args.get("status", "")
    busca  = request.args.get("q", "")
    q      = "SELECT * FROM clientes WHERE user_id=?"
    params = [uid]
    if status:
        q += " AND status=?";  params.append(status)
    if busca:
        q += " AND (nome LIKE ? OR email LIKE ? OR empresa LIKE ?)"
        params += [f"%{busca}%"] * 3
    q += " ORDER BY id DESC"
    with get_db() as conn:
        clientes = conn.execute(q, params).fetchall()
        totais = {
            s: conn.execute(
                "SELECT COUNT(*) FROM clientes WHERE user_id=?" + (" AND status=?" if s else ""),
                (uid, s) if s else (uid,),
            ).fetchone()[0]
            for s in ("", "lead", "ativo", "inativo")
        }
    return render_template(
        "crm/index.html",
        clientes=clientes, totais=totais,
        status_filter=status, busca=busca,
    )


@app.route("/crm/novo", methods=["GET", "POST"])
@login_required
def crm_novo():
    if request.method == "POST":
        uid  = session["user_id"]
        nome = request.form["nome"].strip()
        if not nome:
            flash("Nome é obrigatório.", "erro")
            return render_template("crm/novo.html")
        with get_db() as conn:
            conn.execute(
                "INSERT INTO clientes (user_id,nome,email,telefone,empresa,status) VALUES (?,?,?,?,?,?)",
                (uid, nome,
                 request.form.get("email","").strip(),
                 request.form.get("telefone","").strip(),
                 request.form.get("empresa","").strip(),
                 request.form.get("status","lead")),
            )
        flash("Cliente adicionado.", "sucesso")
        return redirect(url_for("crm"))
    return render_template("crm/novo.html")


@app.route("/crm/<int:cid>")
@login_required
def crm_detalhe(cid):
    uid = session["user_id"]
    with get_db() as conn:
        cliente = conn.execute(
            "SELECT * FROM clientes WHERE id=? AND user_id=?", (cid, uid)
        ).fetchone()
        if not cliente:
            flash("Cliente não encontrado.", "erro")
            return redirect(url_for("crm"))
        notas = conn.execute(
            "SELECT * FROM notas WHERE cliente_id=? ORDER BY id DESC", (cid,)
        ).fetchall()
        deals = conn.execute(
            "SELECT * FROM deals WHERE cliente_id=? AND user_id=?", (cid, uid)
        ).fetchall()
    return render_template("crm/detalhe.html", cliente=cliente, notas=notas, deals=deals)


@app.route("/crm/<int:cid>/editar", methods=["GET", "POST"])
@login_required
def crm_editar(cid):
    uid = session["user_id"]
    with get_db() as conn:
        cliente = conn.execute(
            "SELECT * FROM clientes WHERE id=? AND user_id=?", (cid, uid)
        ).fetchone()
    if not cliente:
        flash("Cliente não encontrado.", "erro")
        return redirect(url_for("crm"))
    if request.method == "POST":
        with get_db() as conn:
            conn.execute(
                "UPDATE clientes SET nome=?,email=?,telefone=?,empresa=?,status=? WHERE id=? AND user_id=?",
                (request.form["nome"].strip(),
                 request.form.get("email","").strip(),
                 request.form.get("telefone","").strip(),
                 request.form.get("empresa","").strip(),
                 request.form.get("status","lead"),
                 cid, uid),
            )
        flash("Cliente atualizado.", "sucesso")
        return redirect(url_for("crm_detalhe", cid=cid))
    return render_template("crm/editar.html", cliente=cliente)


@app.route("/crm/<int:cid>/deletar", methods=["POST"])
@login_required
def crm_deletar(cid):
    uid = session["user_id"]
    with get_db() as conn:
        conn.execute("DELETE FROM notas WHERE cliente_id=?", (cid,))
        conn.execute("DELETE FROM deals WHERE cliente_id=? AND user_id=?", (cid, uid))
        conn.execute("DELETE FROM clientes WHERE id=? AND user_id=?", (cid, uid))
    flash("Cliente removido.", "sucesso")
    return redirect(url_for("crm"))


@app.route("/crm/<int:cid>/nota", methods=["POST"])
@login_required
def crm_nota(cid):
    uid   = session["user_id"]
    texto = request.form.get("texto", "").strip()
    if texto:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO notas (cliente_id, user_id, texto) VALUES (?,?,?)",
                (cid, uid, texto),
            )
    return redirect(url_for("crm_detalhe", cid=cid))


# ── Pipeline ──────────────────────────────────

ETAPAS = ["novo", "contato", "proposta", "fechado", "perdido"]
ETAPAS_LABEL = {
    "novo":     "Novo Lead",
    "contato":  "Em Contato",
    "proposta": "Proposta",
    "fechado":  "Fechado",
    "perdido":  "Perdido",
}


@app.route("/pipeline")
@login_required
def pipeline():
    uid = session["user_id"]
    with get_db() as conn:
        deals = conn.execute(
            """SELECT d.*, c.nome AS cliente_nome
               FROM deals d
               LEFT JOIN clientes c ON c.id = d.cliente_id
               WHERE d.user_id = ?
               ORDER BY d.ordem, d.id""",
            (uid,),
        ).fetchall()
        clientes = conn.execute(
            "SELECT id, nome FROM clientes WHERE user_id=? ORDER BY nome", (uid,)
        ).fetchall()
    por_etapa = {e: [] for e in ETAPAS}
    for d in deals:
        if d["etapa"] in por_etapa:
            por_etapa[d["etapa"]].append(d)
    return render_template(
        "pipeline.html",
        por_etapa=por_etapa, etapas=ETAPAS,
        etapas_label=ETAPAS_LABEL, clientes=clientes,
    )


@app.route("/pipeline/novo", methods=["POST"])
@login_required
def pipeline_novo():
    uid    = session["user_id"]
    titulo = request.form.get("titulo", "").strip()
    if not titulo:
        flash("Título é obrigatório.", "erro")
        return redirect(url_for("pipeline"))
    try:
        valor = float(request.form.get("valor", "0").replace(",", "."))
    except ValueError:
        valor = 0.0
    cliente_id = request.form.get("cliente_id") or None
    etapa      = request.form.get("etapa", "novo")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO deals (user_id,cliente_id,titulo,valor,etapa) VALUES (?,?,?,?,?)",
            (uid, cliente_id, titulo, valor, etapa),
        )
    flash("Deal criado.", "sucesso")
    return redirect(url_for("pipeline"))


@app.route("/pipeline/mover", methods=["POST"])
@login_required
def pipeline_mover():
    uid  = session["user_id"]
    data = request.get_json()
    did  = data.get("deal_id")
    nova = data.get("etapa")
    if nova not in ETAPAS:
        return jsonify(ok=False), 400
    with get_db() as conn:
        conn.execute(
            "UPDATE deals SET etapa=? WHERE id=? AND user_id=?", (nova, did, uid)
        )
    return jsonify(ok=True)


@app.route("/pipeline/<int:did>/deletar", methods=["POST"])
@login_required
def pipeline_deletar(did):
    uid = session["user_id"]
    with get_db() as conn:
        conn.execute("DELETE FROM deals WHERE id=? AND user_id=?", (did, uid))
    flash("Deal removido.", "sucesso")
    return redirect(url_for("pipeline"))


# ── Financeiro ────────────────────────────────

CAT_RECEITA = ["Vendas", "Serviços", "Consultoria", "Recorrente", "Outros"]
CAT_DESPESA = ["Marketing", "Operacional", "Pessoal", "Tecnologia", "Infra", "Outros"]


@app.route("/financeiro")
@login_required
def financeiro():
    uid  = session["user_id"]
    tipo = request.args.get("tipo", "")
    with get_db() as conn:
        q      = "SELECT * FROM transacoes WHERE user_id=?"
        params = [uid]
        if tipo:
            q += " AND tipo=?"; params.append(tipo)
        q += " ORDER BY data DESC, id DESC"
        transacoes    = conn.execute(q, params).fetchall()
        total_receita = conn.execute(
            "SELECT COALESCE(SUM(valor),0) FROM transacoes WHERE user_id=? AND tipo='receita'", (uid,)
        ).fetchone()[0]
        total_despesa = conn.execute(
            "SELECT COALESCE(SUM(valor),0) FROM transacoes WHERE user_id=? AND tipo='despesa'", (uid,)
        ).fetchone()[0]
        receita_mes = conn.execute(
            """SELECT COALESCE(SUM(valor),0) FROM transacoes
               WHERE user_id=? AND tipo='receita'
               AND strftime('%Y-%m',data)=strftime('%Y-%m','now')""",
            (uid,),
        ).fetchone()[0]
        despesa_mes = conn.execute(
            """SELECT COALESCE(SUM(valor),0) FROM transacoes
               WHERE user_id=? AND tipo='despesa'
               AND strftime('%Y-%m',data)=strftime('%Y-%m','now')""",
            (uid,),
        ).fetchone()[0]
    return render_template(
        "financeiro/index.html",
        transacoes=transacoes,
        total_receita=total_receita,
        total_despesa=total_despesa,
        saldo=total_receita - total_despesa,
        receita_mes=receita_mes,
        despesa_mes=despesa_mes,
        tipo_filter=tipo,
    )


@app.route("/financeiro/nova", methods=["GET", "POST"])
@login_required
def financeiro_nova():
    if request.method == "POST":
        uid       = session["user_id"]
        tipo      = request.form.get("tipo", "receita")
        descricao = request.form.get("descricao", "").strip()
        categoria = request.form.get("categoria", "")
        data_tx   = request.form.get("data", str(date.today()))
        if not descricao:
            flash("Descrição é obrigatória.", "erro")
            return render_template("financeiro/nova.html",
                cat_receita=CAT_RECEITA, cat_despesa=CAT_DESPESA, today=str(date.today()))
        try:
            valor = float(request.form.get("valor", "0").replace(",", "."))
        except ValueError:
            valor = 0.0
        with get_db() as conn:
            conn.execute(
                "INSERT INTO transacoes (user_id,tipo,descricao,valor,categoria,data) VALUES (?,?,?,?,?,?)",
                (uid, tipo, descricao, valor, categoria, data_tx),
            )
        flash("Transação registrada.", "sucesso")
        return redirect(url_for("financeiro"))
    return render_template("financeiro/nova.html",
        cat_receita=CAT_RECEITA, cat_despesa=CAT_DESPESA, today=str(date.today()))


@app.route("/financeiro/<int:tid>/deletar", methods=["POST"])
@login_required
def financeiro_deletar(tid):
    uid = session["user_id"]
    with get_db() as conn:
        conn.execute("DELETE FROM transacoes WHERE id=? AND user_id=?", (tid, uid))
    flash("Transação removida.", "sucesso")
    return redirect(url_for("financeiro"))


# ── Admin ─────────────────────────────────────

@app.route("/admin")
@admin_required
def admin():
    with get_db() as conn:
        usuarios         = conn.execute("SELECT * FROM usuarios ORDER BY id").fetchall()
        total_clientes   = conn.execute("SELECT COUNT(*) FROM clientes").fetchone()[0]
        total_deals      = conn.execute("SELECT COUNT(*) FROM deals").fetchone()[0]
        total_transacoes = conn.execute("SELECT COUNT(*) FROM transacoes").fetchone()[0]
    return render_template(
        "admin/index.html",
        usuarios=usuarios,
        total_clientes=total_clientes,
        total_deals=total_deals,
        total_transacoes=total_transacoes,
    )


@app.route("/admin/usuario/<int:uid>/role", methods=["POST"])
@admin_required
def admin_toggle_role(uid):
    if uid == session["user_id"]:
        flash("Você não pode alterar seu próprio papel.", "aviso")
        return redirect(url_for("admin"))
    with get_db() as conn:
        u = conn.execute("SELECT role FROM usuarios WHERE id=?", (uid,)).fetchone()
        if u:
            novo = "admin" if u["role"] == "usuario" else "usuario"
            conn.execute("UPDATE usuarios SET role=? WHERE id=?", (novo, uid))
    flash("Papel atualizado.", "sucesso")
    return redirect(url_for("admin"))


@app.route("/admin/usuario/<int:uid>/ativo", methods=["POST"])
@admin_required
def admin_toggle_ativo(uid):
    if uid == session["user_id"]:
        flash("Você não pode desativar sua própria conta.", "aviso")
        return redirect(url_for("admin"))
    with get_db() as conn:
        u = conn.execute("SELECT ativo FROM usuarios WHERE id=?", (uid,)).fetchone()
        if u:
            conn.execute("UPDATE usuarios SET ativo=? WHERE id=?", (1 - u["ativo"], uid))
    flash("Status atualizado.", "sucesso")
    return redirect(url_for("admin"))


@app.route("/admin/usuario/<int:uid>/deletar", methods=["POST"])
@admin_required
def admin_deletar_usuario(uid):
    if uid == session["user_id"]:
        flash("Você não pode deletar sua própria conta.", "aviso")
        return redirect(url_for("admin"))
    with get_db() as conn:
        for tbl in ("notas", "deals", "transacoes", "clientes"):
            conn.execute(f"DELETE FROM {tbl} WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM usuarios WHERE id=?", (uid,))
    flash("Usuário removido.", "sucesso")
    return redirect(url_for("admin"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
