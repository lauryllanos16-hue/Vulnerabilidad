<?php
// ARCHIVO DE PRUEBA: Intento de bypass de extensión doble (.png.php)
header('Content-Type: text/plain');
echo "DEMOSTRACIÓN DE BYPASS POR DOBLE EXTENSIÓN:\n";
echo "El servidor vulnerable procesa la última extensión y ejecuta PHP.\n";
echo "En el servidor remediado, la extensión .php final es detectada y bloqueada de inmediato.\n";
?>
