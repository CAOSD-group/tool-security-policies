# 1. Cargar librerías
if (!require("tidyverse")) install.packages("tidyverse")
library(tidyverse)

# 2. Leer el archivo
ruta_archivo <- "validation_results_valid_jsons_model_policies02_Z3_1.csv"
df <- read.csv(ruta_archivo, stringsAsFactors = FALSE, na.strings = c("-", ""))

# 3. Preparación de datos base
# Solo trabajamos con las que fueron evaluadas (no Skip)
df_evaluados <- df %>% 
  filter(Secure != "Skip") %>%
  mutate(
    SecurityScore = as.numeric(`SecurityScore.0.100.`),
    Features = as.numeric(Features)
  )

total_configs_evaluadas <- nrow(df_evaluados)

# 4. Procesamiento exhaustivo por Política
resumen_detallado <- df_evaluados %>%
  separate_rows(PoliciesApplied, sep = ";") %>%
  rename(Policy = PoliciesApplied) %>%
  mutate(
    Cumple = ifelse(!is.na(FailedPolicies) & str_detect(FailedPolicies, fixed(Policy)), FALSE, TRUE)
  ) %>%
  group_by(Policy) %>%
  summarise(
    Apariciones = n(),
    Cumplidas = sum(Cumple == TRUE),
    Fallidas = sum(Cumple == FALSE),
    # --- Métricas de Penetración ---
    Pct_Presencia_en_Infra = round((Apariciones / total_configs_evaluadas) * 100, 2),
    # --- Métricas de Éxito ---
    Pct_Exito_Politica = round((Cumplidas / Apariciones) * 100, 2),
    # --- Métricas de Impacto y Tamaño ---
    Features_Totales_Afectadas = sum(Features, na.rm = TRUE),
    Media_Features_por_Config = round(mean(Features, na.rm = TRUE), 2),
    # Score promedio de las configs donde aparece esta política
    Score_Medio_Configs = round(mean(SecurityScore, na.rm = TRUE), 2)
  ) %>%
  arrange(desc(Apariciones))

# 5. Guardar CSV con toda la información
write.csv(resumen_detallado, "resumen_exhaustivo_politicas.csv", row.names = FALSE)

# 6. Gráfico Complementario: Correlación Score vs Features
# Esto ayuda a ver si las configuraciones más grandes son menos seguras
chart_correlacion <- ggplot(df_evaluados, aes(x = Features, y = SecurityScore)) +
  geom_point(aes(color = Secure), size = 3) +
  geom_smooth(method = "lm", color = "gray", linetype = "dashed", se = FALSE) +
  scale_color_manual(values = c("True" = "#2ecc71", "False" = "#e74c3c")) +
  theme_minimal() +
  labs(
    title = "Relación: Tamaño (Features) vs. Seguridad (Score)",
    subtitle = "Cada punto es un archivo de configuración",
    x = "Número de Features",
    y = "Security Score (0-100)"
  )

print("Reporte exhaustivo generado en 'resumen_exhaustivo_politicas.csv'")
print(resumen_detallado)
print(chart_correlacion)