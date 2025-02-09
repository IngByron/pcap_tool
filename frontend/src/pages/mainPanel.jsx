import React, { useState } from "react";
import { Row, Col, Card } from "antd";
import MainHeader from "../components/MainHeader";
import FileUpload from "../components/FileUpload";
import FileHistory from "../components/FileHistory";
import AnalysisDashboard from "../components/AnalysisDashboard";


const MainPanel = () => {
  const [uploadedFile, setUploadedFile] = useState(null);


  const handleFileUpload = (file) => {
    setUploadedFile(file);
  };

  return (
    <>
      <MainHeader/>
      <Row gutter={16} style={{ padding: 20 }}>
        <Col xs={24} md={12}>
          <Card title="Subir Archivo PCAP">
            <FileUpload  />
          </Card>
        </Col>
        <Col xs={24} md={12}>
          <Card title="Historial de Archivos">
            <FileHistory />
          </Card>
        </Col>
      </Row>

      <Row gutter={16} style={{ padding: 20 }}>
        <Col span={24}>
          <Card title="Panel de Análisis">
            <AnalysisDashboard />
          </Card>
        </Col>
      </Row>
      
    </>
  );
};

export default MainPanel;