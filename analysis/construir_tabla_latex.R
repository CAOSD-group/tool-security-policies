# 1. Cargar librerías
if (!require("tidyverse")) install.packages("tidyverse")
library(tidyverse)

# 2. Leer el CSV resumen
# Asegúrate de que el nombre del archivo coincida con el generado anteriormente
df_resumen <- read.csv("resumen_exhaustivo_politicas.csv", stringsAsFactors = FALSE)

# 3. Construir el cuerpo de la tabla
# Usamos glue para inyectar los datos en el formato de celdas solicitado
lineas_tabla <- df_resumen %>%
  mutate(
    # Escapamos los guiones bajos de los nombres de las políticas para LaTeX
    Policy_Escaped = str_replace_all(Policy, "_", "\\\\_"),
    
    # Construcción de la fila
    fila = glue::glue(
      "\\makecell[l]{{\\emph{{{Policy_Escaped}}} \\\\ $\\hookrightarrow$ [Descripción de la política]} & ",
      "[Resource] & [Severity] & {Pct_Presencia_en_Infra}\\% & ",
      "{Pct_Exito_Politica}\\% & [Features] & {Score_Medio_Configs} \\\\"
    )
  ) %>%
  pull(fila)

# 4. Definir la estructura completa del documento/tabla
contenido_tex <- c(
  "% Archivo generado automáticamente por R",
  "\\begin{table}[ht]",
  "  \\caption{Security policies evaluation.}",
  "  \\label{tab:Eval}",
  "  \\centering",
  "  \\scriptsize",
  "  \\begin{tabular}{lccrrrr}",
  "    \\toprule",
  "    \\textbf{Security policy} & \\textbf{K8s resource} & \\textbf{Sev.} & \\textbf{Presence} & \\textbf{Success} & \\textbf{Feat.} & \\textbf{Score Med.} \\\\ \\midrule",
  lineas_tabla,
  "  \\end{tabular}",
  "\\end{table}"
)

# 5. Guardar en un fichero .tex
writeLines(contenido_tex, "tabla_politicas.tex")

# Mensaje de confirmación
print("Archivo 'tabla_politicas.tex' generado con éxito.")