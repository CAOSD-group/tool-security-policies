// YamlDiffViewer.jsx
import React from 'react';
import { DiffEditor } from '@monaco-editor/react';
import { Loader2 } from 'lucide-react';

const YamlDiffViewer = ({ originalYaml, modifiedYaml }) => {
  return (
    <DiffEditor
      height="100%"
      language="yaml"
      theme="vs-light" // We use vs-light for consistency with the application theme
      modified={modifiedYaml || ''}
      options={{
        renderSideBySide: true, // Divided view (GitHub-style)
        readOnly: true,         // Review mode, not editable
        minimap: { enabled: false },
        wordWrap: 'on',
        scrollBeyondLastLine: false,
        fontSize: 14,
      }}
      loading={
        <div className="flex items-center justify-center h-full text-blue-600">
          <Loader2 className="w-8 h-8 animate-spin" />
        </div>
      }
    />
  );
};

export default YamlDiffViewer;