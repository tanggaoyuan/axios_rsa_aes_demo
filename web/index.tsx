import App from './App';
import ReactDom from 'react-dom';

if (module.hot) {
  module.hot.accept();
}

ReactDom.render(<App />, document.querySelector('#root'));
