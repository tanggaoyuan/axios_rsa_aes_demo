import { BrowserRouter, Route, Routes } from 'react-router-dom';
import Home from '@pages/Home';

const App = () => (
    <BrowserRouter>
      <Routes>
        <Route path="/home" element={<Home />} />
        <Route path="/login" element={<div >login</div>} />
      </Routes>
    </BrowserRouter>
  );

export default App;
