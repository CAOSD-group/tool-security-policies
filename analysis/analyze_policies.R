# 1. Cargar la librería
if (!require("tidyverse")) install.packages("tidyverse")
library(tidyverse)

# 2. Configurar la ruta del archivo
# Cambia "mi_analisis.csv" por el nombre real de tu archivo
ruta_archivo <- "validation_results_valid_jsons03_Z3.csv"

# 3. Leer el CSV
# na.strings = "-" convierte los guiones en valores nulos reales para poder operar matemáticamente
df <- read.csv(ruta_archivo, stringsAsFactors = FALSE, na.strings = "-")

# 4. Procesamiento de los datos
resultado <- df %>%
  # Limpiamos: Solo filas con True o False en la columna Secure
  filter(Secure %in% c("True", "False")) %>%
  # Aseguramos que Features sea un número
  mutate(Features = as.numeric(Features)) %>%
  # Extraemos los nombres de las políticas (las 'llaves' del diccionario)
  mutate(PolicyName = str_extract_all(PoliciesApplied, "(?<=')[^']+(?=':)")) %>%
  # Expandimos: Una fila por cada política encontrada
  unnest(PolicyName) %>%
  # Agrupamos por cada política de seguridad detectada
  group_by(PolicyName) %>%
  summarise(
    Total_Configuraciones = n(),
    Es_Secure_True = sum(Secure == "True", na.rm = TRUE),
    Es_Secure_False = sum(Secure == "False", na.rm = TRUE),
    Media_Features = mean(Features, na.rm = TRUE),
    Max_Features = max(Features, na.rm = TRUE)
  ) %>%
  # Ordenamos por las políticas más frecuentes
  arrange(desc(Total_Configuraciones))

# 5. Ver el resultado en consola
print(resultado)

# 6. (Opcional) Guardar este resumen en un nuevo CSV
write.csv(resultado, "resumen_politicas.csv", row.names = FALSE)