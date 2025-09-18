# 🐪 CamelLeaked

<div align="center">

[![CamelLeaked Security Scan](https://github.com/Bulletdev/CamelLeaked/actions/workflows/scan.yml/badge.svg)](https://github.com/Bulletdev/CamelLeaked/actions/workflows/scan.yml)

**A powerful Perl-based security tool for detecting hardcoded secrets in code changes**

[![Perl Version](https://img.shields.io/badge/perl-v5.24%2B-blue)](https://www.perl.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub Actions](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-brightgreen)](/.github/workflows/scan.yml)

</div>

##  O que ele faz?

CamelLeaked é uma ferramenta de segurança defensiva projetada para detectar **segredos hardcoded** (chaves de API, senhas, tokens, etc.) em alterações de código. A ferramenta analisa diffs do Git usando padrões de expressões regulares e detecção de entropia para identificar potenciais vazamentos de credenciais **antes** que sejam commitados.

###  Por que isso é importante?

- **Prevenção de vazamentos**: Detecta credenciais antes que cheguem ao repositório
- **Automação de segurança**: Integra-se perfeitamente com GitHub Actions
- **Notificações inteligentes**: Envia alertas por e-mail para os autores dos commits
- **Falsos positivos controláveis**: Sistema de ignore para casos legítimos

##  Funcionalidades Principais

-  **Detecção por Regex**: 15+ regras pré-configuradas para AWS, GitHub, Google, Stripe, etc.
-  **Análise de Entropia**: Detecta strings de alta entropia que podem ser chaves secretas
-  **Notificações Automáticas**: Envia e-mails detalhados quando segredos são encontrados
-  **Configurável**: Regras personalizáveis via arquivo JSON
-  **Sistema de Ignore**: Comentários `# camel-leaked-ignore` para falsos positivos
-  **CI/CD Ready**: Workflow GitHub Actions pronto para uso
-  **Testado**: Suite completa de testes unitários

##  Instalação

### Pré-requisitos

- Perl 5.24 ou superior
- cpanminus (instalador de módulos CPAN)

### Instalação das Dependências

```bash
# Instalar cpanminus se não tiver
curl -L https://cpanmin.us | perl - App::cpanminus

# Instalar dependências do projeto
cpanm --installdeps .
```

### Verificação da Instalação

```bash
# Testar o script principal
perl bin/camel-leaked.pl --version

# Executar testes
prove -l t/
```

## ⚙ Configuração

### 1. Configurar Regras de Detecção

```bash
# Copiar arquivo de exemplo
cp config/rules.json.example config/rules.json

# Editar regras conforme necessário
vim config/rules.json
```

### 2. Configurar GitHub Secrets

Para habilitar notificações por e-mail, configure os seguintes secrets no seu repositório GitHub:

| Secret | Descrição | Exemplo |
|--------|-----------|---------|
| `SMTP_HOST` | Servidor SMTP | `smtp.gmail.com` |
| `SMTP_PORT` | Porta SMTP | `587` |
| `SMTP_USER` | Usuário SMTP | `security@empresa.com` |
| `SMTP_PASS` | Senha SMTP | `sua_senha_smtp` |
| `FROM_EMAIL` | E-mail remetente | `security@empresa.com` |

#### Como adicionar GitHub Secrets:

1. Vá para seu repositório no GitHub
2. **Settings** → **Secrets and variables** → **Actions**
3. Clique em **New repository secret**
4. Adicione cada secret listado acima

### 3. Adicionar Workflow ao Repositório

Copie o arquivo `.github/workflows/scan.yml` para o seu repositório:

```bash
mkdir -p .github/workflows
cp .github/workflows/scan.yml .github/workflows/camel-leaked.yml
git add .github/workflows/camel-leaked.yml
git commit -m \"Add CamelLeaked security scanning\"
```

##  Uso

### Integração com GitHub Actions

O CamelLeaked funciona automaticamente quando:

1. **Pull Requests** são criados ou atualizados
2. **Pushes** são feitos para branches principais (`main`, `master`, `develop`)

### Uso Manual

```bash
# Escanear diff via STDIN
git diff | perl bin/camel-leaked.pl

# Escanear arquivo de diff específico
perl bin/camel-leaked.pl --diff-file changes.diff

# Usar configuração personalizada
perl bin/camel-leaked.pl --config custom-rules.json

# Desabilitar notificações por e-mail
git diff | perl bin/camel-leaked.pl --no-email

# Ver ajuda
perl bin/camel-leaked.pl --help
```

### Exemplo de Uso em CI/CD

```yaml
- name: Run security scan
  run: |
    git diff origin/main...HEAD | perl bin/camel-leaked.pl
```

## 🛠 Como Funciona

### Arquitetura

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│   GitHub PR     │───▶│ CamelLeaked  │───▶│ Email Alert     │
│                 │    │   Scanner    │    │                 │
└─────────────────┘    └──────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────┐
                       │ Rules Engine │
                       │ (JSON Config)│
                       └──────────────┘
```

### Processo de Detecção

1. **Análise de Diff**: Processa git diff linha por linha
2. **Aplicação de Regras**: Testa cada linha contra padrões regex
3. **Detecção de Entropia**: Identifica strings de alta entropia
4. **Filtros**: Remove falsos positivos e linhas ignoradas
5. **Notificação**: Envia alertas se segredos forem encontrados
6. **Exit Code**: Retorna 1 se segredos encontrados, 0 caso contrário

### Tipos de Detecção

####  Detecção por Regex
Regras pré-configuradas para:
- AWS Access Keys (`AKIA[0-9A-Z]{16}`)
- GitHub Tokens (`ghp_[A-Za-z0-9_]{36,255}`)
- Google API Keys (`AIza[0-9A-Za-z\\-_]{35}`)
- Slack Tokens (`xox[baprs]-[0-9a-zA-Z]{10,48}`)
- E muitos mais...

####  Detecção de Entropia
- Calcula entropia Shannon de strings
- Detecta chaves aleatórias não cobertas por regex
- Configurável (entropia mínima, tamanho mínimo)

##  Exemplos

### Falso Positivo (Como Ignorar)

```python
# Esta linha será ignorada
api_key = \"test_key_1234567890abcdef\"  # camel-leaked-ignore
```

### Estrutura de Regra JSON

```json
{
  \"rules\": [
    {
      \"name\": \"AWS Access Key\",
      \"pattern\": \"AKIA[0-9A-Z]{16}\",
      \"description\": \"AWS Access Key ID\",
      \"example\": \"AKIAIOSFODNN7EXAMPLE\",
      \"enabled\": true
    }
  ]
}
```

### Output de Exemplo

```
🚨 SECRET LEAK DETECTED! 🚨

The following potential secrets were found in the diff:

File: config/database.py
Line: 15
Rule: AWS Access Key
Content: AKIAIOSFODNN7EXAMPLE
Context: aws_access_key = \"AKIAIOSFODNN7EXAMPLE\"
---

📧 Notification email sent to commit author
```

## 🤝 Como Contribuir

### Adicionando Novas Regras

1. Edite `config/rules.json.example`
2. Adicione a nova regra seguindo o formato:

```json
{
  \"name\": \"Nome da Regra\",
  \"pattern\": \"sua_regex_aqui\",
  \"description\": \"Descrição do que detecta\",
  \"example\": \"exemplo_do_que_seria_detectado\",
  \"enabled\": true
}
```

3. Teste a regra:

```bash
echo \"seu_teste_aqui\" | perl bin/camel-leaked.pl
```

### Adicionando Novos Recursos

1. Fork o repositório
2. Crie uma branch: `git checkout -b feature/nova-funcionalidade`
3. Faça suas alterações
4. Adicione testes em `t/`
5. Execute a suite de testes: `prove -l t/`
6. Submeta um Pull Request

### Executando Testes

```bash
# Todos os testes
prove -l t/

# Testes específicos
perl t/01-scanner.t
perl t/02-rules.t

# Com coverage
cover -test
```

##  Roadmap

- [ ] Suporte a mais formatos de diff
- [ ] Interface web para visualização
- [ ] Integração com mais plataformas CI/CD
- [ ] Machine learning para detecção avançada
- [ ] Plugin para IDEs
- [ ] Relatórios em formato JSON/XML

## ❓ FAQ

### Q: O CamelLeaked pode gerar falsos positivos?
**A:** Sim, especialmente com strings longas ou dados codificados. Use `# camel-leaked-ignore` para suprimir.

### Q: Como adicionar suporte para outros serviços de e-mail?
**A:** Configure as variáveis SMTP apropriadas. Suporta Gmail, SendGrid, e qualquer servidor SMTP.

### Q: A ferramenta funciona com repositories privados?
**A:** Sim! Funciona em qualquer repositório GitHub (público ou privado).

### Q: Posso usar em outros sistemas CI/CD?
**A:** Sim! O script Perl pode ser executado em qualquer ambiente que suporte Perl.

## 📄 Licença

Este projeto está licenciado sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🔒 Segurança

- **Nunca** commite credenciais reais no repositório
- Configure adequadamente os GitHub Secrets
- Revise regularmente as regras de detecção
- Reporte problemas de segurança via email privado

## 👥 Autores

**Security Engineering Team**

- Desenvolvido com foco em segurança defensiva
- Mantido pela comunidade Perl
- Contribuições são bem-vindas!

---

<div align=\"center\">

**🔒 Security is everyone's responsibility! 🔒**

[Reportar Bug](../../issues) · [Solicitar Feature](../../issues) · [Documentação](../../wiki)

</div>
