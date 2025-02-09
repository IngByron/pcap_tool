import React, { createContext, useState, useContext } from 'react';

// Crear el contexto
const AnalysisContext = createContext();

// Proveedor de contexto
export const AnalysisProvider = ({ children }) => {
  const [analysisData, setAnalysisData] = useState(null);

  return (
    <AnalysisContext.Provider value={{ analysisData, setAnalysisData }}>
      {children}
    </AnalysisContext.Provider>
  );
};

// Hook personalizado para usar el contexto
export const useAnalysis = () => useContext(AnalysisContext);
