import React from "react";
import MainPanel from "./pages/mainPanel";
import { Layout } from "antd";
import { AnalysisProvider } from './services/AnalysisContext';

const { Content } = Layout;

const App = () => {
  return (
    <AnalysisProvider>
      <Layout style={{ minHeight: "100vh" }}>
      <Content>
        <MainPanel />
      </Content>
    </Layout>
    </AnalysisProvider>
  );
};

export default App;
