import React, { useState, useEffect } from "react";
import { List, Modal, Typography, Spin, Alert } from "antd";
import { fetchFiles } from "../services/api";

const FileHistory = ({ onFileSelect }) => {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedFile, setSelectedFile] = useState(null); // Estado para el archivo seleccionado
  const [modalVisible, setModalVisible] = useState(false); // Estado para el modal de confirmación

  useEffect(() => {
    const loadFiles = async () => {
      setLoading(true);
      try {
        const result = await fetchFiles(); // La respuesta del backend es un objeto
        
        // Asegúrate de que la propiedad 'files' exista y sea un array
        if (result.files && Array.isArray(result.files)) {
          setFiles(result.files); // Accede a los archivos dentro de 'files'
        } else {
          setError("No se encontraron archivos en la respuesta.");
        }
      } catch (error) {
        setError(`Error al cargar los archivos: ${error.message}`);
      }
      setLoading(false);
    };
    loadFiles();
  }, []);

  const handleFileSelect = (file) => {
    setSelectedFile(file); // Guardamos el archivo seleccionado
    setModalVisible(true); // Mostramos el modal de confirmación
  };

  const handleConfirmProcess = () => {
    if (onFileSelect) {
      onFileSelect(selectedFile); // Llamamos a la función onFileSelect pasada como prop
    }
    setModalVisible(false); // Cerramos el modal
  };

  const handleCancel = () => {
    setModalVisible(false); // Cerramos el modal si el usuario cancela
  };

  return (
    <div className="p-2 border border-gray-300 rounded-lg shadow-lg">
  {loading ? (
    <Spin tip="Cargando archivos..." />
  ) : error ? (
    <Alert message={error} type="error" showIcon />
  ) : files.length === 0 ? (
    <p>No hay archivos subidos.</p>
  ) : (
    <div style={{ maxHeight: '200px', overflowY: 'auto' }}> {/* Contenedor con scroll */}
      <List
        size="small"
        bordered
        dataSource={files}
        renderItem={(item) => (
          <List.Item
            onClick={() => handleFileSelect(item)} // Llama a handleFileSelect cuando un archivo es clickeado
            style={{
              cursor: "pointer",
              backgroundColor: selectedFile === item ? "#e6f7ff" : "transparent", // Resalta el archivo seleccionado
              padding: '6px 10px', // Menos espacio entre ítems
            }}
          >
            <Typography.Text style={{ fontSize: '14px' }}>{item}</Typography.Text> {/* Reduce el tamaño de la fuente */}
          </List.Item>
        )}
      />
    </div>
  )}

  {/* Modal de confirmación */}
  <Modal
    title="¿Deseas ejecutar el proceso con este archivo?"
    visible={modalVisible}
    onOk={handleConfirmProcess} // Llama a la función para confirmar el proceso
    onCancel={handleCancel} // Llama a la función para cancelar
    okText="Ejecutar"
    cancelText="Cancelar"
  >
    <p style={{ fontSize: '14px' }}>El archivo seleccionado es: {selectedFile}</p> {/* Reducir el tamaño del texto */}
  </Modal>
</div>

  );
};

export default FileHistory;


