# 1. Cargar librerías
if (!require("tidyverse")) install.packages("tidyverse")
library(tidyverse)

# 2. Leer el archivo (Asegúrate de que el nombre coincida)
ruta_archivo <- "validation_results_valid_jsons03_Z3.csv"
df <- read.csv(ruta_archivo, stringsAsFactors = FALSE, na.strings = "-")

# 3. Procesamiento y Limpieza
resumen_politicas <- df %>%
  # Quitamos las filas que no tienen evaluación de seguridad (las que dicen "Skip")
  filter(Secure %in% c("True", "False")) %>%
  # Convertir Features a número para poder sumarlos
  mutate(Features = as.numeric(Features)) %>%
  # Extraer cada política individual del texto '{'Politica': True...}'
  mutate(Nombre_Politica = str_extract_all(PoliciesApplied, "(?<=')[^']+(?=':)")) %>%
  # Expandir para tener una fila por cada política
  unnest(Nombre_Politica) %>%
  # Agrupar para obtener los totales por política
  group_by(Nombre_Politica) %>%
  summarise(
    Total_Configuraciones = n(),
    Casos_Seguros = sum(Secure == "True"),
    Casos_Inseguros = sum(Secure == "False"),
    Total_Features_Afectadas = sum(Features, na.rm = TRUE)
  ) %>%
  # Ordenar por las políticas que más aparecen
  arrange(desc(Total_Configuraciones))

# 4. Mostrar el resultado final
print("### RESUMEN DE POLÍTICAS DE SEGURIDAD ###")
print(resumen_politicas)

# Opcional: Guardar el resultado en un nuevo archivo
write.csv(resumen_politicas, "analisis_por_politica.csv", row.names = FALSE)