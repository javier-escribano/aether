# Añadir una ruta de ataque a Caelum

El valor del range es que **otros lo extiendan**. Una ruta nueva = una terna completa
**rompe → arregla → detecta**. Sigue esta receta (toma AP01 como referencia viva).

## Checklist de una ruta `APxx`

Una ruta no se considera "lista" hasta tener las **5 piezas**:

- [ ] **1. Flag** en `terraform/variables.tf` → `variable "enable_apXX" { default = false }`.
- [ ] **2. Misconfig como código**: el recurso vulnerable, en el módulo del dominio que toque
      (`entra-identity`, `azure-resources` o `hybrid-ad`), envuelto en `count = var.enable_apXX ? 1 : 0`.
- [ ] **3. Seed** (si Terraform no llega): `scripts/seed-apXX.ps1` idempotente, invocado por `caelum.ps1`.
- [ ] **4. Doc** `docs/attack-paths/APxx-<slug>.md` con la plantilla de abajo.
- [ ] **5. Detección**: `detections/kql/APxx-*.kql` **y** `detections/sigma/APxx-*.yml`.

Y registrar la fila en la tabla *Catálogo* del `README.md`.

## Plantilla del doc de ruta

```markdown
# APxx — <nombre>

- **Capa:** Entra | Azure | Híbrido
- **Coste:** ~0 | bajo | VM
- **MITRE ATT&CK:** Txxxx (<táctica/técnica>)
- **Mapea a cert:** CARTP | CARTE | CRTO | CRTE
- **Precondición:** <qué deja sembrado el range>

## 🎯 Objetivo didáctico
<Qué entiende el alumno al terminar.>

## 🔴 Rompe (cómo se explota)
<Pasos de ataque a nivel de entrenamiento + herramientas públicas de referencia.
Sin armar capacidades nuevas: describe la técnica y enlaza doc/tooling conocido.>

## 🟢 Arregla (remediación)
<Configuración correcta, con el cmdlet/recurso exacto. Idealmente el "antídoto" que
tu módulo aplica cuando el flag pasa a false.>

## 🔵 Detecta
<Qué evento/log lo delata + enlace a detections/kql y detections/sigma.>

## 📚 Referencias
<Enlaces: MITRE, docs MS, writeups públicos.>
```

## Principios

- **Idempotente siempre.** `deploy` dos veces = mismo estado. `reset` quita la vuln sin tocar la base.
- **Realista, no de juguete.** Prefiere misconfigs que has visto en engagements reales.
- **Teardown limpio.** Nada debe sobrevivir a `destroy`.
- **La detección es parte de la ruta, no un extra.** Sin KQL/Sigma, la ruta no entra.

## Flujo git sugerido

```bash
git switch -c ruta/apXX-<slug>
# ... implementa las 5 piezas ...
git commit -m "AP-XX: <nombre> (rompe/arregla/detecta)"
```
