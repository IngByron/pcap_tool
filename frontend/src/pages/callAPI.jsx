import React, { useEffect, useState } from 'react';
import { getInfo } from '../services/api';

const Home = () => {
  const [info, setInfo] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await getInfo();
        setInfo(data);
      } catch (error) {
        console.error("Error fetching data", error);
      }
    };

    fetchData();
  }, []);

  return (
    <div>
      <h1>Información del Sistema</h1>
      {info ? (
        <pre>{JSON.stringify(info, null, 2)}</pre>
      ) : (
        <p>Cargando...</p>
      )}
    </div>
  );
};

export default Home;
