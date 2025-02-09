import React, { useState } from "react";
import { Upload, Button, Modal, List, Alert } from "antd";
import { InboxOutlined, DeleteOutlined, SaveOutlined, PlaySquareOutlined } from "@ant-design/icons";
import ProcessModal from "./ProcessModal";

const FileUpload = () => {
  const [fileList, setFileList] = useState([]);
  const [modalVisible, setModalVisible] = useState(false);
  const [actionType, setActionType] = useState("");
  const [errorMessage, setErrorMessage] = useState(""); 
  const [errorModalVisible, setErrorModalVisible] = useState(false); 


  // Función para validar si el archivo es un archivo .pcap legítimo
  const isValidPcap = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onloadend = () => {
        const buffer = reader.result;
        const magicNumber = new Uint8Array(buffer.slice(0, 4)); 
        if (
          (magicNumber[0] === 0xA1 && magicNumber[1] === 0xB2 && magicNumber[2] === 0xC3 && magicNumber[3] === 0xD4) ||
          (magicNumber[0] === 0xD4 && magicNumber[1] === 0xC3 && magicNumber[2] === 0xB2 && magicNumber[3] === 0xA1) ||
          (magicNumber[0] === 0x0A && magicNumber[1] === 0x0D && magicNumber[2] === 0x0D && magicNumber[3] === 0x0A)
        ) {
          resolve(true); 
        } else {
          reject("El archivo no es un .pcap válido.");
        }
      };

      reader.onerror = () => {
        reject("Error al leer el archivo.");
      };

      reader.readAsArrayBuffer(file);
    });
  };

  const beforeUpload = (file) => {
    if (!file.name.toLowerCase().endsWith(".pcap") && !file.name.toLowerCase().endsWith(".pcapng")) {
      setErrorMessage("Solo se permiten archivos .pcap");
      setErrorModalVisible(true); 
      setFileList([]);
      return Upload.LIST_IGNORE;
    }

    return isValidPcap(file)
      .then(() => {
        setErrorMessage(""); 
        return true; 
      })
      .catch((error) => {
        setErrorMessage(error);
        setErrorModalVisible(true);
        setFileList([]); 
        return Upload.LIST_IGNORE;
      });
  };

  const handleChange = ({ fileList: newFileList }) => {
    if (newFileList.length > 1) {
      newFileList = newFileList.slice(-1);  // Mantén solo el último archivo
    }
    setFileList(newFileList); // Actualiza el estado con el nuevo archivo
  };
  

  const handleProcess = (type) => {
    setActionType(type);
    setModalVisible(true);
  };

  const handleRemoveFile = () => {
    setFileList([]);
  };

  const handleErrorModalClose = () => {
    setErrorModalVisible(false);
  };

  return (
    <div className="selected-file-text file-upload-title p-4 border border-gray-300 rounded-lg shadow-lg">
      <Upload
        beforeUpload={beforeUpload}
        onChange={handleChange}
        fileList={fileList}
        maxCount={1}
        showUploadList={true} 
        customRequest={({ file, onSuccess }) => {
          onSuccess("ok");
        }}
      >
        <Button icon={<InboxOutlined />}>Haz clic para seleccionar archivo</Button>
      </Upload>

      {fileList.length > 0 && (
        <List
          header={<div>Archivo seleccionado</div>}
          bordered
          dataSource={fileList}
          renderItem={(file) => (
            <List.Item
              actions={[<Button icon={<DeleteOutlined />} onClick={handleRemoveFile} />]}
            >
              {file.name}
            </List.Item>
          )}
        />
      )}

      {fileList.length > 0 && (
        <div className="file-upload-buttons mt-4 text-center">
          <Button icon={<PlaySquareOutlined />} type="default" onClick={() => handleProcess("Ejecutando proceso")}>
            Ejecutar Proceso
          </Button>
          <Button icon={<SaveOutlined />} type="primary" onClick={() => handleProcess("Guardando archivo")}>
            Guardar Archivo
          </Button>
        </div>
      )}

      <ProcessModal
        visible={modalVisible}
        onClose={() => setModalVisible(false)}
        actionType={actionType}
        file={fileList.length > 0 ? fileList[0].originFileObj : null} // Pasamos el archivo
      />

      <Modal
        visible={errorModalVisible}
        onCancel={handleErrorModalClose}
        footer={null}
        title="Error en el archivo"
      >
        <Alert message={errorMessage} type="error" showIcon />
      </Modal>
    </div>
  );
};

export default FileUpload;