import React from 'react';
import { Layout, Typography } from 'antd';
import '../App.css'; // Archivo CSS con estilos personalizados

const { Header } = Layout;
const { Title } = Typography;

const MainHeader = () => {
  return (
    <Layout className="layout" style={{ minHeight: '5vh' }}>
      <Header className='titulo-principal'>
        <div className="logo">
          <Title level={3} style={{ color: 'white', textAlign: 'center', padding: '10px 0' }}>
            Sistema Web para el Análisis de Archivos PCAP
          </Title>
        </div>
      </Header>


    </Layout>
  );
};

export default MainHeader;
