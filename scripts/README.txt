Este script analiza con Snort 3.0 y reglas TALOS todos los pcaps de un directorio y extrae los sids resultantes.

EL DIRECTORIO "DIR_PCAPS" DEBE TENER LOS PCAPS QUE QUERAMOS ANALIZAR

dir_pcaps = "/home/dit/Descargas/pcaps/"
dir_analisis_snort = "/home/dit/Escritorio/analisis_ICS_S4x15/"
dir_sids = "/home/dit/Escritorio/salida_ataques_ICS_S4x15/"
comando_snort = "snort -c /usr/local/etc/snort/snort.lua -A full -r"

Cuando estén los pcaps que queremos analizar añadidos al directorio, en la misma línea de comandos y directorio donde se encuentre el script escribiremos "./extrae_flujos.py" para ejecutarlo. Posteriormente, cuando haya finalizado el proceso obtendremos el los 2 directorios restantes los resultados (dir_analisis_snort y dir_sids).
