import chain from '../utils/HttpUtil';

const Home = () => {
    const onClick = () => {
        chain.post('/rsa/product').send({ user: 'user' }).query({ code: 'code' }).then((response) => {
            console.log(response.data);
        });
    };

    return (
        <button onClick={onClick} >请求</button>
    );
};

export default Home;
