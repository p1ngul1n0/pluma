# Pluma
Ferramenta para análise de aplicações Web.

## Módulos
- INFO
  - Apresenta informações do host através de consulta whois,
  - Exibe caso detecte no conteúdo da página, links, palavras chave para dados sensíveis, emails e comentários.
  - Exibe cabeçalhos de resposta HTTP.
- HEADERS
  - Realiza análise de cabeçalhos de segurança existentes.
  - Verifica a existência de informações técnicas em cabeçalhos de resposta.
- COOKIES
  - Verifica a existência de parâmetros 'Secure' e 'HttpOnly' em cookies.
- METHODS
  - Realiza envio de requisições utilizando diferentes métodos HTTP e a subsequente resposta para cada caso.
- AUTOCOMPLETE
  - Caso identifique campo de entrada de senha, verifica a existência do parâmetro 'autocomplete=off'.
- ENUM
  - Realiza enumeração de diretórios através de arquivo 'diretorios.txt'.
- SPIDER
  - Realiza crawling de página.

## Uso
Instale as bibliotecas necessárias para execução
  pip3 install -r requirements
