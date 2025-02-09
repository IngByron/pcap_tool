import React, { useState, useEffect } from "react";
import { Modal, Spin, Alert } from "antd";
import { uploadFile } from "../services/api";  
import { fetchAnalysis } from "../services/api";
import { useAnalysis } from '../services/AnalysisContext';


const ProcessModal = ({ visible, onClose, actionType, file }) => {
  const [loading, setLoading] = useState(true);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const { setAnalysisData } = useAnalysis();
  useEffect(() => {
    if (visible) {
      if (actionType === "Guardando archivo" && file) {
        executeSaveFile(file);
      } else {
        executePacketAnalysis();
      }
    } else {
      resetState();
    }
  });

  const executePacketAnalysis = async () => {
    if (!file) {
      setLoading(false);
      setError(true);
      setErrorMsg("No se seleccionó ningún archivo para analizar.");
      return;
    }
    const response = await fetchAnalysis(file);
      if (response.status !== 200) {
        setError(true);
        setErrorMsg(response.error);
        setSuccess(false);
      } else {
        setSuccess(true);
        setAnalysisData(response.data);
      }
  
      setLoading(false);
  };

  const executeSaveFile = async () => {
    if (!file) {
      setLoading(false);
      setError(true);
      setErrorMsg("No se seleccionó ningún archivo para guardar.");
      return;
    }
    const result = await uploadFile(file);
    if (result.status !== 200) {
      setError(true);
      setErrorMsg(result.error);
      setSuccess(false);
    } else {
      setSuccess(true);
    }

    setLoading(false);
  };

  const resetState = () => {
    setLoading(true);
    setSuccess(false);
    setError(false);
    setErrorMsg("");
  };

  return (
    <Modal open={visible} onCancel={onClose} footer={null} title={actionType}>
      {loading ? (
        <div className="flex justify-center">
          <Spin size="large" />
        </div>
      ) : success ? (
        <Alert message="Acción realizada con éxito" type="success" showIcon />
      ) : error ? (
        <Alert message={errorMsg || "Ha ocurrido un error"} type="error" showIcon />
      ) : null}
    </Modal>
  );
};

export default ProcessModal;

