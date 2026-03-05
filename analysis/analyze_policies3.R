# 1. Cargar librerías
if (!require("tidyverse")) install.packages("tidyverse")
library(tidyverse)

# 2. Leer el archivo
# Tratamos guiones y celdas vacías como NA
ruta_archivo <- "validation_results_valid_jsons_model_policies02_Z3_1.csv"
df <- read.csv(ruta_archivo, stringsAsFactors = FALSE, na.strings = c("-", ""))

# 3. Procesamiento de datos
# Filtramos los archivos que no fueron saltados (Skip)
df_evaluados <- df %>%
  filter(Secure != "Skip")

# Generar el resumen por política
resumen_politicas <- df_evaluados %>%
  # Convertimos la columna de políticas en filas individuales
  separate_rows(PoliciesApplied, sep = ";") %>%
  rename(Policy = PoliciesApplied) %>%
  # Lógica: Si la política NO está en la columna FailedPolicies, entonces se pasó (Passed)
  mutate(
    Se_Cumple = ifelse(!is.na(FailedPolicies) & str_detect(FailedPolicies, fixed(Policy)), 
                       FALSE, TRUE)
  ) %>%
  # Agrupamos por política para los cálculos
  group_by(Policy) %>%
  summarise(
    Num_Configuraciones = n(),
    Pasadas = sum(Se_Cumple == TRUE),
    Fallidas = sum(Se_Cumple == FALSE)
  ) %>%
  # Calculamos el porcentaje de éxito
  mutate(
    Porcentaje_Pasadas = round((Pasadas / Num_Configuraciones) * 100, 2)
  ) %>%
  # Ordenar de mayor a menor presencia
  arrange(desc(Num_Configuraciones))

# 4. Guardar el resumen en un nuevo CSV
write.csv(resumen_politicas, "resumen_politicas_seguridad.csv", row.names = FALSE)

# 5. Mostrar resultado en consola para verificación rápida
print("Resumen de políticas generado:")
print(resumen_politicas)

# 6. Gráfico del SecurityScore (como pediste anteriormente)
df_grafico <- df_evaluados %>%
  mutate(SecurityScore = as.numeric(`SecurityScore.0.100.`))

ggplot(df_grafico, aes(x = reorder(Filename, SecurityScore), y = SecurityScore, fill = SecurityScore)) +
  geom_col() +
  coord_flip() +
  scale_fill_gradient(low = "#e74c3c", high = "#2ecc71") +
  theme_minimal() +
  labs(
    title = "Seguridad por Configuración",
    subtitle = "Basado en SecurityScore (0-100)",
    x = "Archivo JSON",
    y = "Puntuación de Seguridad",
    fill = "Score"
  )