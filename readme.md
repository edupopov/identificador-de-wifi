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

<img width="539" height="241" alt="image" src="https://github.com/user-attachments/assets/b3ea95a9-9844-4854-966e-ff58e458a3bc" />


---

## ⚙️ Funcionalidades

O aplicativo oferece, por meio de um menu simples, opções como:

  Utilitário para:
  - Listar redes Wi-Fi
  - Mostrar senhas
  - Mostrar características (WPA/AES etc.)
  - Listar adaptadores Wi-Fi (hardware + rede + IP + banda + driver)
  - Backup/restauração de perfis Wi-Fi (XML)
  - Excluir perfil Wi-Fi específico
  - Diagnóstico de rede (ping / tracert / arp)
  - Scanner de redes Wi-Fi (site survey básico)
  - Criar novo perfil Wi-Fi (XML + netsh)

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
