import { useState, useRef } from 'react';
import Editor from '@monaco-editor/react';
import { ShieldAlert, ShieldCheck, Upload, Play, Loader2 } from 'lucide-react';

const DEFAULT_YAML = `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  hostNetwork: true
  containers:
  - name: nginx
    image: nginx:latest
`;

function App() {
  const [code, setCode] = useState(DEFAULT_YAML);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  // Maneja el botón de Validar enviando el texto como JSON al backend
  const handleValidate = async () => {
    setLoading(true);
    setError(null);
    setResults(null);

    try {
      const response = await fetch('http://localhost:8080/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ manifest_yaml: code }),
      });

      if (!response.ok) throw new Error('Error en el servidor de validación');
      
      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Maneja la subida de un archivo .yaml
  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      setCode(e.target.result);
    };
    reader.readAsText(file);
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col font-sans">
      {/* Cabecera */}
      <header className="bg-slate-900 text-white p-4 shadow-md flex justify-between items-center">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-8 h-8 text-green-400" />
          <h1 className="text-2xl font-bold tracking-tight">Kube-Sec Analyzer</h1>
        </div>
        <p className="text-slate-400 text-sm">Automated Feature Model Validation</p>
      </header>

      {/* Contenido Principal: Pantalla dividida */}
      <main className="flex-1 flex overflow-hidden p-4 gap-4">
        
        {/* Panel del Editor (Izquierda) */}
        <div className="w-1/2 flex flex-col bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
          <div className="bg-gray-100 p-3 border-b border-gray-200 flex justify-between items-center">
            <h2 className="font-semibold text-gray-700">Manifiesto YAML</h2>
            <div className="flex gap-2">
              {/* Botón Oculto de Subida */}
              <input 
                type="file" accept=".yaml,.yml" ref={fileInputRef}
                onChange={handleFileUpload} className="hidden" 
              />
              <button 
                onClick={() => fileInputRef.current.click()}
                className="flex items-center gap-1 px-3 py-1.5 bg-white border border-gray-300 rounded text-sm text-gray-700 hover:bg-gray-50 cursor-pointer transition"
              >
                <Upload className="w-4 h-4" /> Importar
              </button>
              <button 
                onClick={handleValidate}
                disabled={loading}
                className="flex items-center gap-1 px-4 py-1.5 bg-blue-600 rounded text-sm text-white font-medium hover:bg-blue-700 cursor-pointer transition disabled:opacity-50"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                Analizar Seguridad
              </button>
            </div>
          </div>
          
          <div className="flex-1">
            <Editor
              height="100%"
              defaultLanguage="yaml"
              theme="vs-light"
              value={code}
              onChange={(value) => setCode(value)}
              options={{
                minimap: { enabled: false },
                fontSize: 14,
                wordWrap: 'on',
              }}
            />
          </div>
        </div>

        {/* Panel de Resultados (Derecha) */}
        <div className="w-1/2 flex flex-col bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden overflow-y-auto p-6 bg-gray-50">
          <h2 className="text-xl font-bold text-gray-800 mb-4 border-b border-gray-200 pb-2">Resultados de Auditoría</h2>
          
          {/* Estado Inicial */}
          {!results && !loading && !error && (
            <div className="flex-1 flex flex-col items-center justify-center text-gray-400">
              <ShieldCheck className="w-16 h-16 mb-2 opacity-20" />
              <p>Pega tu YAML o importa un archivo y haz clic en "Analizar Seguridad"</p>
            </div>
          )}

          {/* Manejo de Errores (Ej. Backend apagado) */}
          {error && (
            <div className="p-4 bg-red-50 border border-red-200 text-red-700 rounded-lg">
              <strong>Error de conexión:</strong> {error}
            </div>
          )}

          {/* Resultados de la Evaluación */}
          {results && (
            <div>
              {/* Resumen Global */}
              <div className={`p-4 rounded-lg mb-6 flex items-center gap-3 ${results.secure ? 'bg-green-100 text-green-800 border border-green-200' : 'bg-red-100 text-red-800 border border-red-200'}`}>
                {results.secure ? <ShieldCheck className="w-8 h-8" /> : <ShieldAlert className="w-8 h-8" />}
                <div>
                  <h3 className="text-lg font-bold">
                    {results.secure ? "¡Manifiesto Seguro!" : "Vulnerabilidades Detectadas"}
                  </h3>
                  <p className="text-sm opacity-80">Recursos procesados: {results.scanned_resources}</p>
                </div>
              </div>

              {/* Lista de Vulnerabilidades */}
              {!results.secure && (
                <div className="flex flex-col gap-4">
                  {results.violations.map((violation, index) => (
                    <div key={index} className="bg-white p-4 rounded-lg border border-red-100 shadow-sm border-l-4 border-l-red-500">
                      <div className="flex justify-between items-start mb-2">
                        <h4 className="font-bold text-gray-900">{violation.policy}</h4>
                        <span className="px-2 py-1 bg-red-100 text-red-800 text-xs font-bold rounded uppercase">
                          {violation.severity || "ALTA"}
                        </span>
                      </div>
                      <p className="text-gray-600 text-sm mb-3">{violation.description}</p>
                      
                      {violation.remediation && (
                        <div className="bg-blue-50 text-blue-800 p-3 rounded text-sm border border-blue-100">
                          <strong>💡 Recomendación:</strong> {violation.remediation}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;