# NetAutopsy

**Diagnóstico de red para Linux con evidencias que puedes revisar sin conexión.**

NetAutopsy ejecuta pruebas acotadas, muestra qué observó y formula una hipótesis
a partir de los resultados. Sirve para distinguir, por ejemplo, un fallo de
resolución de nombres de un fallo al conectar a un destino IP.

## Instalación en Fedora 45 (x86_64)

Descarga el RPM y el archivo de sumas de [la versión 0.1.0][release]:

```bash
curl -fLO https://github.com/root465-lipcripto/netautopsy/releases/download/v0.1.0/netautopsy-0.1.0-1.fc45.x86_64.rpm
curl -fLO https://github.com/root465-lipcripto/netautopsy/releases/download/v0.1.0/SHA256SUMS
sha256sum --check SHA256SUMS
sudo dnf install ./netautopsy-0.1.0-1.fc45.x86_64.rpm
```

El RPM se distribuye sin firma de mantenedor. La suma comprueba que el archivo
descargado coincide con el publicado. El programa se ejecuta como usuario normal.
Para otra distribución o arquitectura, compila desde el código fuente.

```bash
netautopsy diagnose
netautopsy diagnose --output report.json
netautopsy inspect report.json
netautopsy diagnose --passive --json
netautopsy diagnose --target 2606:4700:4700::1111 --host example.com
```

`--target` acepta una IP literal para comprobar la ruta y abrir una sola
conexión TCP al puerto 443. El valor por defecto es `1.1.1.1`. `--host` cambia
el nombre consultado mediante el resolver del sistema (por defecto, `example.com`).
`--timeout-ms` permite ajustar el tiempo por comprobación, con 2000 ms por defecto.
`--passive` omite ICMP, TCP y resolución. El diagnóstico sale con código 0 si
generó el informe. Los fallos de red son datos del informe.

## Evidencias de v0.1

| Comprobación | Qué registra | Cómo interpretarla |
| --- | --- | --- |
| Ruta | La ruta que devuelve el kernel para la IP, vía iproute2 y rtnetlink | Interfaz, tabla si se informa, origen y gateway. Una interfaz de túnel puede hacer visible la selección de ruta de una VPN. |
| Enlaces | Estado y contadores de error y descarte | Una captura puntual de hasta 32 interfaces. |
| TCP del kernel | `RetransSegs`, `AttemptFails` y `EstabResets` de `/proc/net/snmp` | Son totales del espacio de nombres. Un valor aislado no demuestra que el incidente actual los causó. |
| Gateway | Un intento ICMP por la interfaz seleccionada | Un túnel sin gateway IP omite la prueba. La falta de respuesta puede deberse a filtrado ICMP. |
| TCP al destino | Resultado del establecimiento de conexión | Confirma el handshake al destino consultado. TLS y HTTP quedan fuera de esta medición. |
| Resolución | Resultado de `getent ahosts` | Usa NSS, que puede recurrir a DNS, cachés o `/etc/hosts`. Un fallo para un nombre no identifica qué servidor o componente falló. |

Ejemplo simulado: la ruta está disponible, el handshake TCP por IP funciona y
el resolver no devuelve direcciones para el dominio. La hipótesis es un posible
problema de resolución de nombres. El resultado se limita al destino probado y al
momento de la captura.

El JSON incluye la versión del esquema, el instante inicial en Unix ms, los
tiempos monotónicos relativos, los estados de cada prueba y la hipótesis.
`inspect` valida el esquema y recalcula la hipótesis desde los estados guardados.
El archivo puede incluir nombres consultados, direcciones IP e interfaces.
`--output` crea un archivo nuevo con permisos `0600` y rechaza reemplazarlo.
La utilidad trabaja con capturas locales. Revisa el informe si vas a compartirlo.

## Desarrollo

Requiere Linux, Rust 1.85 o posterior, Cargo e iproute2. Para las pruebas activas
también se usan `ping` de iputils y `getent` de glibc. El RPM declara estas
dependencias para Fedora.

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release
python3 tests/smoke.py target/release/netautopsy
```

La correlación vive en `src/report.rs` y los recolectores en `src/collect.rs`.
El paquete se recompila a partir del commit actual con `cargo`, `gcc`,
`git` y `rpm-build` en Fedora:

```bash
./packaging/build-rpm.sh
```

## Hoja de ruta

- **0.1** Diagnóstico puntual de rutas, gateway, TCP y resolución. Exportación
  JSON y revisión sin acceso a la red.
- **0.2** Monitorizar cambios de interfaz, dirección y ruta con rtnetlink y
  registrar eventos mientras ocurre el incidente.
- **0.3** Guardar el historial en SQLite y comparar capturas.
- **0.4** Añadir una TUI con Ratatui.
- **0.5** Explorar atribución por proceso y eventos del kernel, con eBPF opcional.
- **1.0** Estabilizar el esquema e incorporar exportación forense y pruebas en
  varios kernels y distribuciones.

[release]: https://github.com/root465-lipcripto/netautopsy/releases/tag/v0.1.0
