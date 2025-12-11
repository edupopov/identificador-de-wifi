# WiFi Support Toolkit (PowerShell)

Aplicação em PowerShell criada para auxiliar **analistas de suporte** na identificação rápida das características de conexão Wi-Fi em estações de trabalho Windows.

> 🧑‍💻 Aplicativo criado por **Eduardo Popovici**

---

## 🎯 Objetivo

Em muitos cenários de suporte, o analista precisa descobrir rapidamente:

- Quais redes Wi-Fi já foram configuradas na máquina  
- Qual rede está em uso no momento  
- A intensidade do sinal da conexão  
- Dados de IP, gateway, DNS e máscara de rede  
- Senha (key) das redes salvas, quando necessário para troubleshooting  

Este script oferece um **menu interativo em PowerShell** que centraliza essas informações em um único lugar, facilitando o diagnóstico de problemas de conectividade.

---

## ⚙️ Funcionalidades

O aplicativo oferece, por meio de um menu simples, opções como:

1. **Listar redes Wi-Fi configuradas no equipamento**
   - Exibe todos os perfis de Wi-Fi conhecidos pelo Windows.

2. **Exibir senha de uma rede Wi-Fi salva**
   - Abre um submenu com a lista de redes.
   - Ao selecionar uma rede, o script mostra a **senha (key)** configurada para aquele SSID.

3. **Características das interfaces Wi-Fi**
   - Lista as placas de rede Wi-Fi (hardware) disponíveis:
     - Nome/modelo da placa
     - Endereço MAC
     - ID de hardware e outras características relevantes
   - Informa **qual SSID** cada placa está utilizando (se estiver conectada).
   - Mostra também a **força do sinal** da conexão.

4. **Detalhes da conexão de rede**
   - Exibe:
     - Endereço IP da interface conectada
     - Gateway padrão
     - Servidores DNS
     - Máscara de sub-rede
     - Representação **CIDR** da rede

---

## 🧩 Requisitos

- Windows 10 ou superior (recomendado Windows 10/11)
- PowerShell 5.1 ou superior  
- Permissão para executar scripts (pode ser necessário ajustar a Execution Policy):

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

🚀 Como usar

Clone o repositório ou faça download do script

git clone https://github.com/SEU-USUARIO/SEU-REPOSITORIO.git


Abra o PowerShell como usuário com permissões adequadas.

Navegue até a pasta do script:

cd "Caminho\para\SEU-REPOSITORIO"


Execute o script:

.\wifi-toolkit.ps1


Use o menu interativo
Siga as opções exibidas na tela para listar redes, visualizar senhas ou consultar detalhes de conexão.

📁 Estrutura sugerida do repositório
.
├── wifi-toolkit.ps1   # Script principal em PowerShell
├── README.md          # Este arquivo
└── assets/            # (Opcional) Screenshots, imagens, etc.

🧾 Licença

Defina aqui a licença do projeto (por exemplo, MIT, GPLv3, etc.).
Exemplo:

Este projeto está licenciado sob os termos da licença MIT.

✉️ Autor

Aplicativo criado por Eduardo Popovici.

Sinta-se à vontade para abrir Issues e Pull Requests com sugestões de melhoria, correções ou novas funcionalidades.
