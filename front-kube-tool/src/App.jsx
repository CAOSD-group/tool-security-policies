import { useState, useRef, useEffect } from 'react';
import Editor from '@monaco-editor/react';
import { ShieldAlert, ShieldCheck, Upload, Play, Loader2, Info, AlertCircle, ChevronDown, ChevronUp } from 'lucide-react';

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
  const [systemMessages, setSystemMessages] = useState([]); 
  const fileInputRef = useRef(null);  
  const [showPassedPolicies, setShowPassedPolicies] = useState(false);
  // Referencias para controlar Monaco Editor ---
  const editorRef = useRef(null);
  const monacoRef = useRef(null);
  const decorationsRef = useRef(null);
  const handleEditorDidMount = (editor, monaco) => {
    editorRef.current = editor;
    monacoRef.current = monaco;
    decorationsRef.current = editor.createDecorationsCollection([]);
  };

  // Estado para las políticas expandidas
  const [expandedPassed, setExpandedPassed] = useState({});
  
  const togglePassedPolicy = (policyName) => {
    setExpandedPassed(prev => ({
      ...prev,
      [policyName]: !prev[policyName]
    }));
  };

  const handleValidate = async () => {
    setLoading(true);
    setError(null);
    setExpandedPassed({});
    setSystemMessages([]);
    setResults({ secure: true, scanned_resources: 0, violations: [] }); // Inicializamos vacío

    try {
      const response = await fetch('http://127.0.0.1:8080/validate-stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ manifest_yaml: code }),
      });

      if (!response.ok) throw new Error('Error en el servidor de validación');

      // Leemos el stream de datos
      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let done = false;
      let buffer = ""; // Para guardar trozos de JSON incompletos

      while (!done) {
        const { value, done: readerDone } = await reader.read();
        done = readerDone;
        if (value) {
          buffer += decoder.decode(value, { stream: true });
          
          // Procesamos el buffer línea por línea (\n)
          let lines = buffer.split('\n');
          // El último elemento puede estar incompleto, lo dejamos en el buffer
          buffer = lines.pop(); 

          for (let line of lines) {
            if (line.trim() === '') continue;
            
            const chunk = JSON.parse(line);
            
            // Lógica según el tipo de mensaje que nos mande Python
            if (chunk.status === 'info') {
              console.log("Progreso:", chunk.message);
              setSystemMessages(prev => [...prev, { type: 'info', text: chunk.message }]);
              // Aquí podrías actualizar un estado para mostrar un mensajito de "Analizando Pod..."
            } 
            else if (chunk.status === 'violation') {
              // Añadimos la vulnerabilidad a la lista EN TIEMPO REAL
              setResults(prev => ({
                ...prev,
                secure: false, // En cuanto hay una, ya no es seguro
                violations: [...prev.violations, chunk.data]
              }));
            } 
            else if (chunk.status === 'done') {
              setResults(prev => ({
                ...prev,
                scanned_resources: chunk.scanned_resources,
                passed_policies: chunk.passed_policies || []
              }));
            }
            else if (chunk.status === 'error') {
              // setError(chunk.message);
              setSystemMessages(prev => [...prev, { type: 'error', text: chunk.message }]);
            }
          }
        }
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };
  // Función para inyectar y resaltar el texto cambiado---
  const applyChangesAndHighlight = (oldYaml, newYaml) => {
    setCode(newYaml);
    
    // Delay para que Monaco reciba el nuevo 'code'
    setTimeout(() => {
      if (!editorRef.current || !monacoRef.current) return;

      const oldLines = oldYaml.split('\n');
      const newLines = newYaml.split('\n');
      const newDecorations = [];

      newLines.forEach((line, index) => {
        // Si la línea es diferente y no es un simple espacio vacío
        if (line !== oldLines[index] && line.trim() !== '') {
          newDecorations.push({
            range: new monacoRef.current.Range(index + 1, 1, index + 1, 1),
            options: {
              isWholeLine: true,
              className: 'monaco-highlight-line', // Clase CSS que inyectaremos abajo
            }
          });
        }
      });

      // Aplicar decoración
      if (decorationsRef.current) {
        decorationsRef.current.set(newDecorations);
        // Quitar el color amarillo a los 3 segundos
        setTimeout(() => decorationsRef.current.set([]), 3000);
      }
    }, 100);
  };

  // Botón para reparar todas las vulnerabilidades ---
  const handleFixAll = async () => {
    let allActions = [];
    results.violations.forEach(vuln => {
      if (vuln.remediation_actions) {
        allActions = [...allActions, ...vuln.remediation_actions];
      }
    });

    if (allActions.length === 0) return;

    try {
      const response = await fetch('http://127.0.0.1:8080/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ manifest_yaml: code, actions: allActions }),
      });

      if (!response.ok) throw new Error('Error al parchear');
      const data = await response.json();

      if (data.status === 'success') {
        applyChangesAndHighlight(code, data.remediated_yaml);
        setSystemMessages(prev => [...prev, { type: 'info', text: 'Todas las políticas auto-corregidas con éxito.' }]);
      }
    } catch (err) {
      setSystemMessages(prev => [...prev, { type: 'error', text: err.message }]);
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

// Llama al backend para corregir automáticamente el YAML
  const handleRemediate = async (actionsList) => {
    try {
      const response = await fetch('http://127.0.0.1:8080/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          manifest_yaml: code,
          actions: actionsList // Se envia la lista al backend para que sepa qué corregir
        }),
      });

      if (!response.ok) throw new Error('Error al parchear el archivo');
      
      const data = await response.json();
      
      // Actualizamos el editor de Monaco con el nuevo código corregido
      if (data.status === 'success') {
        //setCode(data.remediated_yaml);
        applyChangesAndHighlight(code, data.remediated_yaml);
        // Opcional: Mostrar un mensaje verde de éxito en el sistema
        setSystemMessages(prev => [...prev, { type: 'info', text: ' YAML auto-corregido con éxito. Vuelve a Analizar.' }]);
      }
    } catch (err) {
      setSystemMessages(prev => [...prev, { type: 'error', text: err.message }]);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col font-sans">
      {/* Cabecera */}
      <style>{`
        .monaco-highlight-line {
          background-color: #76ec80 !important;
        }
      `}</style>

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
              onMount={handleEditorDidMount}
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
        {/* Título y Botón de Reparar Todo */}
          <div className="flex justify-between items-center mb-4 border-b border-gray-200 pb-2">
            <h2 className="text-xl font-bold text-gray-800">Resultados de Auditoría</h2>
            {results && !results.secure && results.violations.some(v => v.remediation_actions?.length > 0) && (
              <button 
                onClick={handleFixAll}
                className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded shadow text-sm font-semibold transition flex items-center gap-1 cursor-pointer"
              >
                Reparar Todo
              </button>
            )}
          </div>
            
          {/* Estado Inicial */}
          {!results && !loading && !error && systemMessages.length === 0 && (
            <div className="flex-1 flex flex-col items-center justify-center text-gray-400">
              <ShieldCheck className="w-16 h-16 mb-2 opacity-20" />
              <p>Pega tu YAML o importa un archivo y haz clic en "Analizar Seguridad"</p>
            </div>
          )}

          {/* Manejo de Errores Críticos(Ej. Backend apagado) */}
          {error && (
            <div className="p-4 bg-red-50 border border-red-200 text-red-700 rounded-lg">
              <strong>Error de conexión:</strong> {error}
            </div>
          )}
          {/* Mensajes del Sistema (Info y Errores de Parseo) */}
          {systemMessages.length > 0 && (
            <div className="flex flex-col gap-2 mb-6">
              {systemMessages.map((msg, idx) => (
                <div key={idx} className={`p-3 text-sm rounded-lg flex items-start gap-2 border ${
                  msg.type === 'error' ? 'bg-orange-50 text-orange-800 border-orange-200' : 'bg-blue-50 text-blue-800 border-blue-200'
                }`}>
                  {msg.type === 'error' ? <AlertCircle className="w-5 h-5 shrink-0" /> : <Info className="w-5 h-5 shrink-0" />}
                  <span>{msg.text}</span>
                </div>
              ))}
            </div>
          )}
          {/* Resultados de la Evaluación */}
          {results && (
            <div>
              {/* Resumen Global */}
              {results.scanned_resources === 0 && !loading && results.violations.length === 0 ? (
                <div className="p-4 rounded-lg mb-6 flex items-center gap-3 bg-gray-100 text-gray-500 border border-gray-200">
                  <Info className="w-8 h-8" />
                  <div>
                    <h3 className="text-lg font-bold">Sin recursos analizados</h3>
                    <p className="text-sm">El manifiesto no contiene recursos válidos para evaluar.</p>
                  </div>
                </div>
              ) : (
                <div className={`p-4 rounded-lg mb-6 flex items-center gap-3 ${results.secure ? 'bg-green-100 text-green-800 border border-green-200' : 'bg-red-100 text-red-800 border border-red-200'}`}>
                  {results.secure ? <ShieldCheck className="w-8 h-8" /> : <ShieldAlert className="w-8 h-8" />}
                  <div>
                    <h3 className="text-lg font-bold">
                      {results.secure ? "¡Manifiesto Seguro!" : "Vulnerabilidades Detectadas"}
                    </h3>
                    <p className="text-sm opacity-80">Recursos procesados válidos: {results.scanned_resources}</p>
                  </div>
                </div>
              )}

              {/* NUEVO: GRÁFICO VISUAL (Balance de Seguridad) */}
              {(() => {
                const passedCount = results.passed_policies ? results.passed_policies.length : 0;
                const failedCount = results.violations ? results.violations.length : 0;
                const totalPolicies = passedCount + failedCount;
                
                if (totalPolicies === 0) return null;

                const passedPercentage = Math.round((passedCount / totalPolicies) * 100);
                const failedPercentage = 100 - passedPercentage;

                return (
                  <div className="mb-6 p-4 bg-white border border-gray-200 rounded-lg shadow-sm">
                    <h3 className="text-sm font-bold text-gray-700 mb-3 flex items-center gap-2">
                      Balance de Seguridad ({totalPolicies} políticas evaluadas)
                    </h3>
                  
                    {/* Barra de progreso apilada */}
                    <div className="flex h-4 w-full rounded-full overflow-hidden bg-gray-100">
                      <div 
                        style={{ width: `${passedPercentage}%` }} 
                        className="bg-green-500 hover:bg-green-400 transition-all duration-500"
                        title={`${passedCount} Superadas`}
                      ></div>
                      <div 
                        style={{ width: `${failedPercentage}%` }} 
                        className="bg-red-500 hover:bg-red-400 transition-all duration-500"
                        title={`${failedCount} Violadas`}
                      ></div>
                    </div>
                    
                    {/* Leyendas con porcentajes */}
                    <div className="flex justify-between mt-2 text-xs font-semibold">
                      <span className="text-green-700">
                        {passedCount} Superadas ({passedPercentage}%)
                      </span>
                      <span className="text-red-700">
                        {failedCount} Violadas ({failedPercentage}%)
                      </span>
                    </div>
                  </div>
                );
              })()}

              {/* Show the policies approved under the icon vulnerabilities */}
              {results.passed_policies && results.passed_policies.length > 0 && (
                <div className="mt-4 mb-6">
                  
                  {/* Cabecera Principal Colapsable (El Acordeón Maestro) */}
                  <div 
                    onClick={() => setShowPassedPolicies(!showPassedPolicies)}
                    className="flex items-center justify-between p-3 bg-green-50/80 border border-green-200 rounded-lg cursor-pointer hover:bg-green-100 transition-colors mb-3"
                  >
                    <div className="flex items-center gap-2">
                      <ShieldCheck className="w-5 h-5 text-green-600" />
                      <h3 className="text-md font-bold text-green-800">
                        Ver políticas superadas con éxito ({results.passed_policies.length})
                      </h3>
                    </div>
                    {/* Flecha indicadora principal */}
                    {showPassedPolicies ? (
                      <ChevronUp className="w-5 h-5 text-green-700" />
                    ) : (
                      <ChevronDown className="w-5 h-5 text-green-700" />
                    )}
                  </div>
                  
                  {/* Lista de Políticas (Solo se renderiza si el acordeón maestro está abierto) */}
                  {showPassedPolicies && (
                    <div className="flex flex-col gap-2 mt-2 animate-in fade-in slide-in-from-top-2 duration-200">
                      {results.passed_policies.map((policyObj, idx) => (
                        <div key={idx} className="bg-green-50 border border-green-200 rounded-lg overflow-hidden transition-all">
                          
                          {/* Cabecera Clicable Individual */}
                          <div 
                            onClick={() => togglePassedPolicy(policyObj.policy)}
                            className="flex justify-between items-center p-3 cursor-pointer hover:bg-green-100 transition-colors"
                          >
                            <div className="flex items-center gap-2">
                              <span className="font-semibold text-sm text-green-900">
                                {policyObj.policy}
                              </span>
                              <span className="px-2 py-0.5 bg-green-200 text-green-800 text-[10px] font-bold rounded uppercase">
                                {policyObj.severity || 'OK'}
                              </span>
                              <span className="px-2 py-0.5 bg-yellow-200 text-green-800 text-[10px] font-bold rounded uppercase">
                                {policyObj.tool || 'Desconocida'}
                              </span>
                            </div>
                            {expandedPassed[policyObj.policy] ? (
                              <ChevronUp className="w-4 h-4 text-green-700" />
                            ) : (
                              <ChevronDown className="w-4 h-4 text-green-700" />
                            )}
                          </div>
                          
                          {/* Contenido Expandible (Descripción) */}
                          {expandedPassed[policyObj.policy] && (
                            <div className="px-4 pb-3 pt-1 text-sm text-green-800 border-t border-green-200/50 bg-green-50/50">
                              <p className="mt-2 text-gray-700 font-medium">
                                {policyObj.description}
                              </p>
                            </div>
                          )}

                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
              {/* Lista de Vulnerabilidades EN TIEMPO REAL */}
              {!results.secure && (
                <div className="flex flex-col gap-4">
                  <div className="flex items-center gap-2 mb-3">
                    <ShieldAlert className="w-5 h-5 text-red-600" />
                    <h3 className="text-md font-bold text-gray-800">
                      Políticas incumplidas ({results.violations.length})
                    </h3>
                  </div>
                  {results.violations.map((violation, index) => (
                    <div key={index} className="bg-white p-4 rounded-lg border border-red-100 shadow-sm border-l-4 border-l-red-500">
                      
                      <div className="flex justify-between items-start mb-2">
                        <h4 className="font-bold text-gray-900">{violation.policy}</h4>
                        {/* Contenedor flexible para alinear las etiquetas juntas */}
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-1 bg-red-200 text-red-800 text-[10px] font-bold rounded uppercase">
                            {violation.severity || "ALTA"}
                          </span>
                          
                          {/* NUEVO: Etiqueta de la herramienta */}
                          {violation.tool && (
                            <span className="px-2 py-1 bg-yellow-200 text-red-800 text-[10px] font-bold rounded uppercase">
                              {violation.tool}
                            </span>
                          )}
                        </div>
                      </div>
                      <p className="text-gray-600 text-sm mb-3">{violation.description}</p>
                      
                      {violation.remediation && (
                        <div className="bg-blue-50 text-blue-800 p-3 rounded text-sm border border-blue-100 mb-3">
                          <strong>💡 Recomendación:</strong> {violation.remediation}
                        </div>
                      )}

                      {/* ¡NUEVO BOTÓN DE AUTOCORRECCIÓN! */}
                      {violation.remediation_actions && violation.remediation_actions.length > 0 && (
                      <button 
                        onClick={() => handleRemediate(violation.remediation_actions)}
                        className="mt-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium py-1.5 px-3 rounded shadow-sm transition cursor-pointer"
                      >
                        Auto-Corregir Problema
                      </button>
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