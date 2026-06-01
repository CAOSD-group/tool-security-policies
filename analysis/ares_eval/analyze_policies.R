# 1. Cargar librerías
if (!require("tidyverse")) install.packages("tidyverse")
library(tidyverse)

# 2. Leer el archivo
ruta_archivo <- "policies_30k.csv"
df <- read.csv(ruta_archivo, stringsAsFactors = FALSE, na.strings = c("-", ""))

# 3A. Resumen global de la columna Secure (True / False / Skip)
resumen_secure <- df %>%
  group_by(Secure) %>%
  summarise(
    Conteo = n()
  ) %>%
  mutate(
    Porcentaje = round((Conteo / sum(Conteo)) * 100, 2)
  )

print("Resumen de valores en la columna Secure:")
print(resumen_secure)

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
    Pct_Presencia_en_Infra = round((Apariciones / total_configs_evaluadas) * 100, 2),
    Pct_Exito_Politica = round((Cumplidas / Apariciones) * 100, 2),
    Features_Totales_Afectadas = sum(Features, na.rm = TRUE),
    Media_Features_por_Config = round(mean(Features, na.rm = TRUE), 2),
    Score_Medio_Configs = round(mean(SecurityScore, na.rm = TRUE), 2)
  ) %>%
  arrange(desc(Apariciones))

# 5. Guardar CSV con toda la información
write.csv(resumen_detallado, "resumen_exhaustivo_politicas.csv", row.names = FALSE)

# 6. Gráfico Complementario
chart_correlacion <- ggplot(df_evaluados, aes(x = Features, y = SecurityScore)) +
  geom_point(aes(color = SecurityScore), size = 3) +
  #geom_smooth(method = "lm", color = "gray", linetype = "dashed", se = FALSE) +
  scale_color_gradient(
    low = "red",
    high = "green",
    limits = c(0, 100),
    name = "Security Score"
  ) +
  theme_minimal() +
  labs(
    x = "Number of features in configuration",
    y = "Security Score (0-100)"
  )

print("Reporte exhaustivo generado en 'resumen_exhaustivo_politicas.csv'")
print(resumen_detallado)
print(chart_correlacion)