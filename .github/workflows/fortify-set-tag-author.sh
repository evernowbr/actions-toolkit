#!/usr/bin/env bash
# ============================================
# Script integrado: Aplicar tag "Author" e
# processar vulnerabilidades do Fortify SSC
# ============================================

# ==========================
# Configurações
# ==========================
FORTIFY_URL=""   # URL da API Fortify SSC
FORTIFY_TOKEN=""  # Token de autenticação
PROJECT_VERSION_ID="21"   # ID da versão do projeto no Fortify SSC
REPO_DIR="${GITHUB_WORKSPACE}" # Diretório atual do repositório git (para git blame)

# ==========================
# Verifica se a tag Author existe
# ==========================
echo "Verificando custom tags no Fortify..."

response=$(curl -s -w "%{http_code}" -H "Authorization: FortifyToken $FORTIFY_TOKEN" \
  "$FORTIFY_URL/customTags?start=0&limit=100&q=hidden%3Afalse")

code="${response: -3}"
body="${response::-3}"

[ "$code" != "200" ] && echo "Erro HTTP $code" && exit 1
echo "$body" | jq empty >/dev/null 2>&1 || { echo "JSON inválido"; exit 1; }

guid=$(echo "$body" | jq -r '.data[] | select(.name=="Author" and .customTagType=="CUSTOM") | .guid')
if [ -z "$guid" ]; then
    echo "Tag 'Author' com tipo 'CUSTOM' não encontrada."
    exit 1
fi
echo "Tag 'Author' encontrada! GUID: $guid"

# ==========================
# Verifica se a tag Author já está aplicada ao projeto
# ==========================
echo "Verificando se a tag Author está aplicada ao projeto..."

response=$(curl -s -w "%{http_code}" -H "Authorization: FortifyToken $FORTIFY_TOKEN" \
  "$FORTIFY_URL/projectVersions/$PROJECT_VERSION_ID/customTags?start=0&limit=100")

code="${response: -3}"
body="${response::-3}"

[ "$code" != "200" ] && echo "Erro HTTP $code" && exit 1
echo "$body" | jq empty >/dev/null 2>&1 || { echo "JSON inválido"; exit 1; }

echo "Tags atualmente aplicadas ao projeto:"
echo "$body" | jq -r '.data[] | "GUID: \(.guid)  Nome: \(.name // "N/A")  Tipo: \(.customTagType // "N/A")"'

aplicada=$(echo "$body" | jq -r --arg guid "$guid" '.data[] | select(.guid==$guid) | .guid')
if [ -n "$aplicada" ]; then
    echo "A tag Author já está habilitada no projeto."
else
    echo "A tag Author ainda não está habilitada. Aplicando..."
    payload=$(echo "$body" | jq -r '.data[].guid' | jq -R . | jq -s 'map({guid:.})' | jq --arg guid "$guid" '. + [{"guid":$guid}]')
    curl -s -X PUT -H "Authorization: FortifyToken $FORTIFY_TOKEN" \
        -H "Content-Type: application/json" -d "$payload" \
        "$FORTIFY_URL/projectVersions/$PROJECT_VERSION_ID/customTags"
    echo "Tag Author aplicada com sucesso!"
fi

# ==========================
# Baixa issues do Fortify
# ==========================
responseIssues=$(curl -s -g \
    -X GET "$FORTIFY_URL/projectVersions/$PROJECT_VERSION_ID/issues?orderby=id" \
    -H "Accept: application/json" -H "Content-Type: application/json" \
    -H "Authorization: FortifyToken $FORTIFY_TOKEN")

VULN_FILE="$REPO_DIR/fortify_vulnerabilities.json"
echo "$responseIssues" > "$VULN_FILE"

# ==========================
# Processa cada vulnerabilidade crítica/alta e aplica tag Author
# ==========================
jq -c '.data[] | select((.enginePriority=="Critical" or .enginePriority=="High") and (.issueStatus=="Unreviewed" or .primaryTag=="Exploitable"))' "$VULN_FILE" |
while read -r issue; do
    issueId=$(echo "$issue" | jq -r '.id')
    filePath=$(echo "$issue" | jq -r '.fullFileName')
    lineNumber=$(echo "$issue" | jq -r '.lineNumber')
    fixedPath="${filePath#$REPO_DIR/}"
    authorMail="N/A"
    if [ -f "$fixedPath" ] && [ "$lineNumber" != "null" ] && [ "$lineNumber" -gt 0 ]; then
        blameOutput=$(git blame -L "$lineNumber,$lineNumber" --porcelain "$fixedPath" 2>/dev/null)
        foundMail=$(echo "$blameOutput" | grep '^author-mail' | head -n 1 | cut -d' ' -f2 | sed 's/[<>]//g')
        [ -n "$foundMail" ] && authorMail="$foundMail"
    fi
    echo "Issue ID: $issueId  Arquivo: $filePath  Linha: $lineNumber  Autor: $authorMail"

    payloadAuthor=$(jq -n --arg id "$issueId" --arg rev "$(echo "$issue" | jq -r '.revision')" \
        --arg guid "$guid" --arg email "$authorMail" \
        '{
            type: "AUDIT_ISSUE",
            values: {
                issues: [{id: ($id|tonumber), revision: ($rev|tonumber)}],
                customTagAudit: [{customTagGuid: $guid, textValue: $email}],
                comment: "",
                hasTagComment: false
            }
        }')

    curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: FortifyToken $FORTIFY_TOKEN" \
        -d "$payloadAuthor" \
        "$FORTIFY_URL/projectVersions/$PROJECT_VERSION_ID/issues/action?silent=true"
done

echo "Processo concluído: todas as vulnerabilidades críticas/altas foram marcadas com o Author."
