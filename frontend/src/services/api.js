import axios from 'axios';

const API_URL = "http://localhost:5000"; // Asegúrate de que coincide con el backend

// Crear instancia de Axios
const api = axios.create({
  baseURL: API_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Obtener lista de archivos subidos
export const fetchFiles = async () => {
  try {
    const response = await api.get("/files");
    return response.data;
  } catch (error) {
    return [];
  }
};

// Subir archivo al servidor
export const uploadFile = async (file) => {
  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await api.post("/upload", formData, {
      headers: {
        "Content-Type": "multipart/form-data", // Muy importante cuando se suben archivos
      },
    });
    return response;
  } catch (error) {
    return { error: error.response?.data?.message || "Error de conexión con el servidor" }; // Manejo de error
  }
};

export const fetchAnalysis = async (file) => {
  try {
    const formData = new FormData();
    formData.append("file", file);
    const response = await api.post("/analyze", formData, {
      headers: {
        "Content-Type": "multipart/form-data", // Muy importante cuando se suben archivos
      },
    });
    return response;
  } catch (error) {
    return { error: error.response?.data?.message || "Error de conexión con el servidor" }; // Manejo de error
  }
};


// Obtener información general (como en tu ejemplo)
export const getInfo = async () => {
  try {
    const response = await api.get('/info');
    return response.data;
  } catch (error) {
    throw error;
  }
};
