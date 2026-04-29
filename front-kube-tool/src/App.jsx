import { useState, useRef, useEffect } from 'react';
import Editor, { DiffEditor } from '@monaco-editor/react';
import { ShieldAlert, ShieldCheck, Upload, Play, Loader2, Info, AlertCircle, ChevronDown, ChevronUp, FileSearch, CheckCircle, XCircle, RefreshCw, Wrench } from 'lucide-react';
//import YamlDiffViewer from './components/YamlDiffViewer';

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
  const [showLogHistory, setShowLogHistory] = useState(false);
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
  const [fixedPolicies, setFixedPolicies] = useState(new Set());
  const [globalFixApplied, setGlobalFixApplied] = useState(false);
  const [currentPolicyFixing, setCurrentPolicyFixing] = useState(null); //Save the policy that is being fixed at the moment, to show a loading state in that specific violation card
  // Estado para las políticas expandidas
  const [expandedPassed, setExpandedPassed] = useState({});

  // 2. NUEVOS ESTADOS PARA LA VISTA DUAL (AUDITORÍA VS ESTRUCTURA SAT)
  // =========================================================================
  const [activeTab, setActiveTab] = useState('audit'); // 'audit' | 'structure'
  const [structuralData, setStructuralData] = useState(null);
  const [loadingStructure, setLoadingStructure] = useState(false);
  // === ESTADOS PARA EL VISOR DIFF ===
  const [showDiff, setShowDiff] = useState(false);
  const [proposedYaml, setProposedYaml] = useState("");

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
    setFixedPolicies(new Set());
    //setGlobalFixApplied(false);
    setCurrentPolicyFixing(null);
    
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
              // Aquí podrías actualizar un estado para mostrar un mensaje de "Analizando Pod..."
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
  // FUNCIÓN PARA ATACAR AL ENDPOINT SAT
  const checkStructure = async () => {
    setLoadingStructure(true);
    setStructuralData(null);
    try {
      const res = await fetch('http://127.0.0.1:8080/validate-structure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ manifest_yaml: code })
      });
      const data = await res.json();
      setStructuralData(data);
    } catch (error) {
      console.error(error);
      setStructuralData({ status: 'error', message: 'Error de red al conectar con el servidor SAT.' });
    } finally {
      setLoadingStructure(false);
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
              className: 'monaco-highlight-line',
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
    setCurrentPolicyFixing(null);

    //let allActions = [];
    let remainingActions = [];
    results.violations.forEach(vuln => {

    if (!fixedPolicies.has(vuln.policy) && vuln.remediation_actions) {
      remainingActions = [...remainingActions, ...vuln.remediation_actions];
    }
    });

      //if (vuln.remediation_actions) {
        //allActions = [...allActions, ...vuln.remediation_actions];
      //}
      //});

    //if (allActions.length === 0) return;
    if (remainingActions.length === 0) {
      setSystemMessages(prev => [...prev, { type: 'info', text: 'No hay más acciones automáticas disponibles para aplicar.' }]);
      return;
    }
    
    try {
      const response = await fetch('http://127.0.0.1:8080/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ manifest_yaml: code, actions: remainingActions }),
      });

      if (!response.ok) throw new Error('Error al parchear');
      const data = await response.json();

      if (data.status === 'success') {
        setProposedYaml(data.remediated_yaml); 
        setShowDiff(true); 
        setSystemMessages(prev => [...prev, { type: 'info', text: 'Revisa los cambios propuestos en el panel (Diff).' }]);
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
  const handleRemediate = async (violation) => {
    setCurrentPolicyFixing(violation); // Guardamos quién causó el arreglo
    try {
      const response = await fetch('http://127.0.0.1:8080/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          manifest_yaml: code,
          actions: violation.remediation_actions // Pasamos las acciones al backend
        }),
      });

      if (!response.ok) throw new Error('Error al parchear el archivo');
      
      const data = await response.json();
      
      if (data.status === 'success') {
        setProposedYaml(data.remediated_yaml); 
        setShowDiff(true); 
        setSystemMessages(prev => [...prev, { type: 'info', text: 'Revisa los cambios propuestos en el panel (Diff).' }]);
      }
    } catch (err) {
      setSystemMessages(prev => [...prev, { type: 'error', text: err.message }]);
    }
  };

  return (
    <div className="h-screen bg-gray-50 flex flex-col font-sans">
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
          {/* CABECERA SUPERIOR (Solo para importar y analizar) */}
          <div className="bg-gray-100 p-3 border-b border-gray-200 flex justify-between items-center">
            <h2 className="font-semibold text-gray-700 flex items-center gap-2">
              {showDiff ? (
                <>
                  <FileSearch className="w-5 h-5 text-indigo-600" />
                  Revisión de Cambios (Changes View)
                </>
              ) : (
                "Manifiesto YAML"
              )}
            </h2>
            
            <div className="flex gap-2">
              {/* Ocultamos los botones superiores si estamos en modo Diff para evitar clics por inercia */}
              {!showDiff && (
                <>
                  <input 
                    type="file" accept=".yaml,.yml" ref={fileInputRef}
                    onChange={handleFileUpload} className="hidden" 
                  />
                  <button 
                    onClick={() => fileInputRef.current.click()}
                    className="flex items-center gap-1 px-3 py-1.5 bg-white border border-gray-300 rounded text-sm text-gray-700 hover:bg-gray-50 cursor-pointer transition"
                    title='Import your local YAML'
                  >
                    <Upload className="w-4 h-4" /> Importar
                  </button>
                  <button 
                    onClick={handleValidate}
                    disabled={loading}
                    title='Start the validation of the manifest in the template!'
                    className="flex items-center gap-1 px-4 py-1.5 bg-blue-600 rounded text-sm text-white font-medium hover:bg-blue-700 cursor-pointer transition disabled:opacity-50"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                    Analizar Seguridad
                  </button>
                </>
              )}
            </div>
          </div>
          
          {/* ZONA DE EDITORES */}
          <div className="flex-1 relative flex flex-col min-h-0">
            {/* Contenedor de Monaco Editor (Ocupa el espacio restante) */}
            <div className="flex-1 relative">
              {/* 1. VISOR DIFF (Oculto con CSS si no toca) */}
              <div className={showDiff ? "block h-full absolute inset-0" : "hidden"}>
                <DiffEditor
                  height="100%"
                  language="yaml"
                  theme="vs-light"
                  original={code ? code.replace(/\r\n/g, '\n') : ''}
                  modified={proposedYaml ? proposedYaml.replace(/\r\n/g, '\n') : ''}
                  options={{
                    renderSideBySide: true,
                    readOnly: true,
                    minimap: { enabled: false },
                    wordWrap: 'on',
                    scrollBeyondLastLine: false,
                    fontSize: 14,
                  }}
                />
              </div>

              {/* 2. EDITOR NORMAL (Oculto con CSS si hay Diff) */}
              <div className={!showDiff ? "block h-full absolute inset-0" : "hidden"}>
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

            {/* BARRA INFERIOR DE ACCIÓN (Solo aparece en modo Diff) */}
            {showDiff && (
              <div className="bg-slate-50 border-t border-slate-200 p-3 flex justify-between items-center shadow-[0_-4px_6px_-1px_rgba(0,0,0,0.05)] z-10">
                <div className="flex items-center gap-2 text-sm text-slate-500">
                  <Info className="w-4 h-4 text-blue-500" />
                  <span>Revisa las líneas resaltadas antes de aplicar los parches al manifiesto.</span>
                </div>
                
                <div className="flex gap-3">
                  <button 
                    onClick={() => {
                      setShowDiff(false);
                      setCurrentPolicyFixing(null); // Reset if discarding
                      setSystemMessages(prev => [...prev, { type: 'info', text: 'Cambios descartados. Se mantiene el YAML original.' }]);
                    }}
                    title='Descarta los cambios y manten el YAML original'
                    className="flex items-center gap-1 px-4 py-2 bg-white border border-red-200 rounded-md text-sm text-red-600 hover:bg-red-50 cursor-pointer transition shadow-sm"
                  >
                    <XCircle className="w-4 h-4" /> Descartar
                  </button>
                  
                  <button 
                    onClick={() => {
                      setCode(proposedYaml);
                      setShowDiff(false);
                      
                      if (currentPolicyFixing) {
                        // Usamos violation.policy como identificador único
                        setFixedPolicies(prev => new Set(prev).add(currentPolicyFixing.policy));
                      } else {
                        setGlobalFixApplied(true);
                      }
                      setCurrentPolicyFixing(null); // Reseteamos

                      setSystemMessages(prev => [...prev, { type: 'info', text: 'Cambios de seguridad aplicados al manifiesto.' }]);
                    }}
                    title="Aplica este código corregido a tu editor principal"
                    className="flex items-center gap-1 px-5 py-2 bg-green-600 rounded-md text-sm text-white hover:bg-green-700 cursor-pointer transition shadow-sm"
                  >
                    <CheckCircle className="w-4 h-4" /> Aceptar Cambios
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Panel de Resultados (Derecha) */}
        
        <div className="w-1/2 flex flex-col bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden overflow-y-auto p-6 bg-gray-50">
          {/* 4. SELECTOR DE PESTAÑAS DUAL */}
          {/* ================================================================= */}
          <div className="flex space-x-2 mb-4 bg-gray-200 p-1 rounded-lg w-fit shrink-0">
            <button 
              onClick={() => setActiveTab('audit')}
              className={`px-4 py-2 text-sm font-semibold flex items-center gap-2 rounded-md transition-all ${
                activeTab === 'audit' ? 'bg-white shadow-sm text-blue-700' : 'text-gray-600 hover:bg-gray-300'
              }`}
            >
              <ShieldCheck className="w-4 h-4" /> Auditoría de Seguridad (Z3)
            </button>
            
            <button 
              onClick={() => {
                setActiveTab('structure');
                checkStructure(); // Llama a PySAT inmediatamente al cambiar de pestaña
              }}
              className={`px-4 py-2 text-sm font-semibold flex items-center gap-2 rounded-md transition-all ${
                activeTab === 'structure' ? 'bg-white shadow-sm text-purple-700' : 'text-gray-600 hover:bg-gray-300'
              }`}
            >
              <FileSearch className="w-4 h-4" /> Esquema K8s (SAT)
            </button>
          </div>

          <div className="flex-1 overflow-y-auto pr-2">
            {/* PESTAÑA 1: AUDITORÍA DE SEGURIDAD (Tu código original intacto) */}        
            {activeTab === 'audit' && (
              <>
                {/* Título y Botón de Reparar Todo */}
                  <div className="flex justify-between items-center mb-4 border-b border-gray-200 pb-2">
                    <h2 className="text-xl font-bold text-gray-800">Resultados de Auditoría</h2>
                    {results && !results.secure && results.violations.some(v => v.remediation_actions?.length > 0) && (
                      <button 
                        // Si ya se aplicó el global, este botón sirve como atajo para re-analizar
                        onClick={globalFixApplied ? handleValidate : handleFixAll}
                        disabled={loading}
                        title={
                          globalFixApplied
                            ? "Vuelve a analizar para confirmar la seguridad en la política reparada."
                            : "Aplica automáticamente parches a todas las políticas que aún no has reparado."
                        }
                        className={`px-4 py-2 rounded shadow text-sm font-semibold transition flex items-center gap-2 ${
                          loading
                            ? "opacity-50 cursor-not-allowed bg-gray-400 text-white"
                            : globalFixApplied
                              ? "bg-amber-500 hover:bg-amber-600 text-white ring-2 ring-amber-200 ring-offset-1 cursor-pointer"
                              : "bg-indigo-600 hover:bg-indigo-700 text-white cursor-pointer"
                        }`}
                      >
                        {globalFixApplied ? (
                          <>
                            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : 'animate-spin-slow'}`} /> 
                            Volver a Analizar
                          </>
                        ) : (
                          <>
                            <Wrench className="w-4 h-4" /> 
                            {fixedPolicies.size > 0 ? "Reparar Restantes" : "Reparar Todo"}
                          </>
                        )}
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
                  {/* PANEL DE MENSAJES DEL SISTEMA */}
                  {systemMessages.length > 0 && (
                    <div className="mb-6 flex flex-col gap-2">
                      {/* Mensaje Principal (Siempre el último) */}
                      <div className="flex justify-between items-center bg-blue-50 text-blue-800 p-3 rounded-md border border-blue-200 shadow-sm">
                        <div className="flex items-center gap-2">
                          <Info className="w-5 h-5" />
                          <span className="font-medium text-sm">
                            {systemMessages[systemMessages.length - 1].text}
                          </span>
                        </div>
                        
                        {/* Botón para desplegar historial si hay más de 1 mensaje */}
                        {systemMessages.length > 1 && (
                          <button 
                            onClick={() => setShowLogHistory(!showLogHistory)} 
                            className="text-xs font-semibold underline hover:text-blue-900 cursor-pointer"
                          >
                            {showLogHistory ? "Ocultar historial" : `Ver historial (${systemMessages.length - 1})`}
                          </button>
                        )}
                      </div>

                      {/* Historial Desplegable */}
                      {showLogHistory && (
                        <div className="max-h-32 overflow-y-auto pl-4 border-l-2 border-blue-200 space-y-1.5 animate-in fade-in slide-in-from-top-2">
                          {/* Mostramos todos menos el último, en orden inverso (más recientes primero) */}
                          {systemMessages.slice(0, -1).reverse().map((msg, idx) => (
                            <div key={idx} className="text-xs text-slate-500 flex items-center gap-2">
                              <span className="w-1.5 h-1.5 rounded-full bg-slate-400"></span>
                              {msg.text}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                  {/* Resultados de la Evaluación */}
                  {results && (
                    <div>
                      {/* Resumen Global */}
                      {loading ? (
                        <div className="p-4 rounded-lg mb-6 flex items-center gap-3 bg-blue-50 text-blue-800 border border-blue-200 shadow-sm animate-pulse">
                          <Loader2 className="w-8 h-8 animate-spin text-blue-600" />
                          <div>
                            <h3 className="text-lg font-bold">Analizando manifiesto...</h3>
                            <p className="text-sm opacity-80">Evaluando políticas de seguridad con el motor Z3.</p>
                          </div>
                        </div>
                      ) : results.scanned_resources === 0 && results.violations.length === 0 ? (
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
                              {results.secure ? "¡Manifiesto Seguro!" : "MISconfigurations Detectadas"}
                            </h3>
                            <p className="text-sm opacity-80">Recursos procesados válidos: {results.scanned_resources}</p>
                          </div>
                        </div>
                      )}

                      {/* GRÁFICO VISUAL (Balance de Seguridad) */}
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
                                title={`${failedCount} Incumplidas`}
                              ></div>
                            </div>
                            
                            {/* Leyendas con porcentajes */}
                            <div className="flex justify-between mt-2 text-xs font-semibold">
                              <span className="text-green-700">
                                {passedCount} Superadas ({passedPercentage}%)
                              </span>
                              <span className="text-red-700">
                                {failedCount} Incumplidas ({failedPercentage}%)
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

                              {/* BOTÓN DE AUTOCORRECCIÓN DINÁMICO */}
                              {violation.remediation_actions && violation.remediation_actions.length > 0 && (
                                (() => {
                                  // Comprobamos si esta política en concreto ya fue aceptada
                                  const isFixed = fixedPolicies.has(violation.policy) || globalFixApplied;
                                  
                                  return (
                                    <button 
                                      onClick={isFixed ? handleValidate : () => handleRemediate(violation)}
                                      title={isFixed 
                                        ? "Ya se aplicó la correción para la política. Vuelve a analizar para confirmar que el problema se ha resuelto." 
                                        : "Aplica automáticamente los parches sugeridos para esta vulnerabilidad específica."
                                      }
                                      className={`mt-2 text-sm font-medium py-1.5 px-3 rounded shadow-sm transition cursor-pointer flex items-center gap-1 w-fit ${
                                        isFixed 
                                          ? "bg-amber-500 hover:bg-amber-600 text-white ring-2 ring-amber-200 ring-offset-1" 
                                          : "bg-indigo-600 hover:bg-indigo-700 text-white"
                                      }`}
                                    >
                                      {isFixed ? (
                                        <>
                                          <RefreshCw className="w-4 h-4 animate-spin-slow" /> Volver a Analizar
                                        </>
                                      ) : (
                                        <>
                                          <Wrench className="w-4 h-4" /> Auto-Corregir Problema
                                        </>
                                      )}
                                    </button>
                                  );
                                })()
                              )}  
                        </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
            </div>
            {/* PESTAÑA 2: VALIDACIÓN ESTRUCTURAL (SAT SOLVER) */}
            {/* ================================================================= */}
            {activeTab === 'structure' && (
              <div className="flex flex-col h-full">
                <div className="bg-white p-6 rounded-xl border shadow-sm flex-1">
                  <div className="border-b border-gray-200 pb-3 mb-6">
                    <h2 className="text-xl font-bold text-gray-800">Validación del Esquema K8s</h2>
                    <p className="text-sm text-gray-500 mt-1">
                      Comprueba restricciones obligatorias (Mandatory) y relaciones estructurales (Cross-Tree Constraints) usando el solver SAT.
                    </p>
                  </div>
                  
                  {loadingStructure ? (
                    <div className="flex flex-col items-center justify-center h-40 space-y-4">
                      <Loader2 className="w-10 h-10 animate-spin text-purple-600" />
                      <p className="text-gray-500 font-medium animate-pulse">Compilando características y resolviendo SAT...</p>
                    </div>
                  ) : (
                    <>
                      {/* Estado inicial / Si no hay datos por un error en la carga */}
                      {!structuralData && (
                        <div className="flex flex-col items-center justify-center h-40 text-gray-400">
                          <FileSearch className="w-12 h-12 mb-2 opacity-20" />
                          <p>Ocurrió un error o no se inició la validación.</p>
                        </div>
                      )}

                      {/* RESULTADO: VÁLIDO */}
                      {structuralData?.status === 'valid' && (
                        <div className="bg-green-50 border border-green-200 p-6 rounded-lg shadow-sm">
                          <div className="flex items-start gap-4">
                            <CheckCircle className="w-10 h-10 text-green-600 flex-shrink-0" />
                            <div>
                              <h3 className="text-xl font-bold text-green-800">Manifiesto Estructuralmente Válido</h3>
                              <p className="text-green-700 mt-2 text-md leading-relaxed">
                                {structuralData.message}
                              </p>
                              {structuralData.time !== undefined && (
                                <p className="text-xs text-green-600 mt-4 font-mono bg-green-100 w-fit px-2 py-1 rounded">
                                  ✓ Resuelto en {structuralData.time}s via Glucose3 (SAT)
                                </p>
                              )}
                            </div>
                          </div>
                        </div>
                      )}

                      {/* RESULTADO: INVÁLIDO O ERROR */}
                      {(structuralData?.status === 'invalid' || structuralData?.status === 'error') && (
                        <div className="bg-red-50 border border-red-200 p-6 rounded-lg shadow-sm">
                          <div className="flex items-start gap-4">
                            <XCircle className="w-10 h-10 text-red-600 flex-shrink-0" />
                            <div className="w-full">
                              <h3 className="text-xl font-bold text-red-800">Error Estructural Detectado</h3>
                              
                              {structuralData.source && (
                                <div className="mt-2 inline-block px-2 py-1 bg-red-100 text-red-800 text-xs font-bold rounded uppercase">
                                  Fuente: {structuralData.source}
                                </div>
                              )}
                              
                              <p className="text-red-700 mt-3 font-medium bg-white/50 p-3 rounded border border-red-100">
                                {structuralData.message}
                              </p>

                              {structuralData.time !== undefined && (
                                <p className="text-xs text-red-500 mt-4 font-mono bg-red-100 w-fit px-2 py-1 rounded">
                                  Rechazado en {structuralData.time}s via Glucose3 (SAT)
                                </p>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            )}
          </div>
      </main>
    </div>
  );
}

export default App;