<!-- PlanVenture README -->
# Planventure API 🚁
A Flask-based REST API backend for the Planventure application.

## Getting Started 👩🏽‍💻
1. Fork this repository to your GitHub account.  
2. Switch to the `api-start` branch (se quiser começar do zero).  
3. Clone o repositório localmente.

Você encontra próximos passos no README da branch `api-start`.

## Build with Me + GitHub Copilot 🚀
Vídeo: [Youtube](https://www.youtube.com/watch?v=CJUbQ1QiBUY)  
Post: [Blog GitHub](https://github.blog/ai-and-ml/github-copilot/github-for-beginners-building-a-rest-api-with-copilot/)  

[![Build API Copilot](https://github.com/user-attachments/assets/a9e6f202-81c1-4b5e-9a77-6f03ee55938c)](https://www.youtube.com/watch?v=CJUbQ1QiBUY)

## Visão Geral do Backend
A API é construída com Flask usando um padrão de "application factory" em [`create_app`](planventure/backend/app.py).  
Principais módulos:
- Configuração: [`config.py`](planventure/backend/config.py)
- Inicialização de app: [`app.py`](planventure/backend/app.py)
- Modelos: [`User`](planventure/backend/models/user.py), [`Viagem`](planventure/backend/models/viagem.py)
- Rotas de autenticação: [`routes/auth.py`](planventure/backend/routes/auth.py)
- Rotas de viagens: [`routes/viagens.py`](planventure/backend/routes/viagens.py)
- Middleware (auth, rate limit, validação): `middleware/`
- Comandos utilitários: [`manage.py`](planventure/backend/manage.py)
- Migração simples: [`migrate_db.py`](planventure/backend/migrate_db.py)

## Arquitetura e Tecnologias
- Flask + Blueprints
- SQLite (dev) via SQLAlchemy
- JWT (access + refresh) via utilitários: [`JWTUtils`](planventure/backend/models/user.py)
- Rate limiting decorador: `rate_limited` em `middleware`
- Validação JSON: `validate_json`
- Controle de propriedade de recurso: `require_ownership`
- Itinerário de viagem armazenado como JSON (campo `itinerario_json` no modelo [`Viagem`](planventure/backend/models/viagem.py))

## Requisitos
- Python 3.10+
- pip / venv
- (Opcional) Bruno / Insomnia / Postman para testar rotas

## Instalação e Execução
```bash
git clone <seu-fork-ou-este-repo>
cd planventure/backend

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt  # (se existir)

# Definir variáveis (exemplos)
export FLASK_ENV=development
export FLASK_APP=app.py
export SECRET_KEY="dev-secret"
# (Opcional) export SQLALCHEMY_DATABASE_URI="sqlite:///planventure-dev.db"

# Inicializar DB
python manage.py init_db

# Criar usuário
python manage.py create_user --email test@example.com --password 123456 --username test

# Rodar servidor
python app.py
```

Servidor padrão: http://localhost:5000

Endpoint raiz `/` retorna metadados (veja [`home` handler](planventure/backend/app.py)) incluindo listas de endpoints.

## Variáveis de Ambiente Importantes
- SECRET_KEY
- JWT_SECRET_KEY (fallback para SECRET_KEY)
- SQLALCHEMY_DATABASE_URI
- FLASK_ENV (development | production)
- FLASK_DEBUG (True/False)
- FLASK_PORT (default 5000)

Definidas em [`Config`](planventure/backend/config.py).

## Estrutura do Banco
Modelo [`User`](planventure/backend/models/user.py):
- id, email (único), username (único), password_hash
- flags: is_admin, is_verified
- timestamps

Modelo [`Viagem`](planventure/backend/models/viagem.py):
- id, user_id (FK), destino, data_inicio, data_fim
- Campos opcionais: titulo, descricao, latitude, longitude, budget
- status: planejando | confirmada | em_andamento | concluida | cancelada
- is_public (privacidade)
- itinerario_json (armazenamento estruturado)
- created_at / updated_at

## Comandos de Gerenciamento
Executados via [`manage.py`](planventure/backend/manage.py):
```bash
python manage.py init_db
python manage.py check_db
python manage.py create_user --email ... --password ... [--admin]
python manage.py list_users
python manage.py reset_db
```

Migração simples (adicionar colunas novas se faltarem):
```bash
python migrate_db.py
```

## Autenticação
Fluxo JWT em [`routes/auth.py`](planventure/backend/routes/auth.py):
- POST /api/auth/register
- POST /api/auth/login
- POST /api/auth/refresh
- POST /api/auth/logout (se implementado no client)
- GET /api/auth/profile
- PUT /api/auth/update-profile
- POST /api/auth/change-password
- POST /api/auth/validate-token
- POST /api/auth/check-email

Tokens criados por [`JWTUtils.generate_access_token`](planventure/backend/models/user.py) e `generate_refresh_token`.

Enviar Authorization: Bearer <access_token> nas rotas protegidas.

## Rotas de Viagens
(Arquivo: [`routes/viagens.py`](planventure/backend/routes/viagens.py))

Protegidas por `@jwt_required()` exceto públicas:
- GET /api/viagens/ (listar viagens do usuário, filtros: ?search=&limit=&offset=)
- POST /api/viagens/ (criar viagem)
- GET /api/viagens/public (listar viagens públicas)
- GET /api/viagens/<id>
- PUT /api/viagens/<id> (update parcial; todos campos opcionais)
- DELETE /api/viagens/<id>
- PATCH /api/viagens/<id>/status (atualiza somente status)
- PUT /api/viagens/<id>/itinerary (atualiza somente itinerário)
- GET /api/viagens/search (busca avançada - se implementada)
- GET /api/viagens/stats (estatísticas - se implementada)
- GET /api/viagens/public (explorar públicas)

Exemplo criação:
```json
{
  "destino": "Paris, France",
  "data_inicio": "2024-12-10",
  "data_fim": "2024-12-20",
  "titulo": "Férias",
  "status": "planejando",
  "is_public": true,
  "itinerario": [
    { "day": 1, "activities": ["Eiffel Tower"] }
  ]
}
```

Validações:
- Datas futuro e início < fim (vide lógica em `create_trip`)
- Status validado em [`update_trip_status`](planventure/backend/routes/viagens.py)
- Itinerário tratado via `set_itinerario` em [`Viagem`](planventure/backend/models/viagem.py)

## Middlewares / Decorators
Localizados em `middleware/` e importados em rotas:
- `jwt_required` (injeta `current_user`)
- `rate_limited`
- `validate_json`
- `require_ownership` (garante que o usuário é dono do recurso)

## Rate Limiting
Exemplos:
- Registro: `@rate_limited(max_requests=5, window_minutes=15)`
- Criação de viagem: `max_requests=20` / 60 min

## Respostas Padrão
Formato típico:
```json
{
  "success": true,
  "message": "...",
  "trip": { ... },
  "pagination": { "total": 0, "limit": 10, "offset": 0, "has_more": false }
}
```

## Execução em Produção (Sugestão)
- Definir SECRET_KEY segura
- Usar banco Postgres ou MySQL (alterar `SQLALCHEMY_DATABASE_URI`)
- Servir via Gunicorn + Reverse Proxy (Nginx)
- Ativar logs estruturados

## Testes Rápidos (cURL)
```bash
# Login
curl -X POST http://localhost:5000/api/auth/login \
 -H "Content-Type: application/json" \
 -d '{"email":"test@example.com","password":"123456"}'

# Criar viagem
curl -X POST http://localhost:5000/api/viagens/ \
 -H "Authorization: Bearer <TOKEN>" \
 -H "Content-Type: application/json" \
 -d '{"destino":"Roma","data_inicio":"2024-11-01","data_fim":"2024-11-05"}'
```

## Próximos Passos (Ideias)
- Paginação também em viagens públicas
- Filtros por data / status
- Upload de mídias
- Notificações
- Testes automatizados (pytest)

## Suporte
Consulte [SUPPORT.md](planventure/SUPPORT.md)

## Licença
Verifique (se aplicável) arquivo LICENSE.
