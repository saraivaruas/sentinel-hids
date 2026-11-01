// Reglas YARA básicas de Sentinel contra puertas traseras web (escritas para este proyecto, licencia MIT).
// Se usan solo si tienes el programa «yara» instalado. Puedes agregar tus reglas en /etc/sentinel/yara/*.yar

rule sentinel_php_eval_decodificado
{
    meta:
        descripcion = "PHP que ejecuta con eval datos decodificados (base64, gzip, rot13)"
    strings:
        $a = /eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/ nocase
    condition:
        $a
}

rule sentinel_php_ejecuta_la_peticion
{
    meta:
        descripcion = "PHP que pasa datos de la petición web a una función que ejecuta comandos o código"
    strings:
        $a = /(eval|assert|system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        $a
}

rule sentinel_php_funcion_desde_la_peticion
{
    meta:
        descripcion = "PHP que llama a una función cuyo nombre llega por la petición ($_POST['f']($_POST['x']))"
    strings:
        $a = /\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/
    condition:
        $a
}

rule sentinel_shell_inversa
{
    meta:
        descripcion = "Shell inversa clásica (bash o nc hacia una IP)"
    strings:
        $a = /bash\s+-i\s+>&\s*\/dev\/tcp\/[0-9.]+\/[0-9]+/
        $b = /\bnc(at)?\b[^\n]{0,40}\s-e\s+\/bin\/(ba)?sh/
    condition:
        any of them
}
