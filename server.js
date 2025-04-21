const express = require('express');
const jwt = require('jsonwebtoken');
const fs= require('fs').promises;
const cors = require('cors');
const bcrypt = require('bcrypt');
const path=require('path');

const app =express();//CRIAÇÃO DA APLICAÇÃO
app.use(express.json());
app.use(cors());

const port =process.env.PORT ||  3000;

//CRIANDO AS CHAVES DE ASSINATURA DO JWT
const SECRET_KEY ="0123456789";//CHAVE PARA ASSINAR O TOKEN
const REFRESH_SECRET_KEY ="9876543210"//SEGUNDA CHAVE PARA RENOVAR O TOKEN

//ARQUIVOS DO BANCO DE DADOS

const Autores_File = path.join(__dirname,'data','autores.json');
const Editoras_File= path.join(__dirname,'data','editoras.json');
const Categorias_File = path.join(__dirname,'data','categorias.json');
const Livros_File = path.join(__dirname,'data','livros.json');
const Usuarios_File = path.join(__dirname,'data','usuarios.json');


//VERIFICAÇÃO DO TOKEN JWT -MIDDLEWARE

const verificaToken = (req, res, next)=> {
    const authCabecalho = req.headers.authorization;

    //verifica se o cabeçalho de autorização existe
    if(!authCabecalho){
        return res.status(401).json({error:"Nenhum Token fornecido"});
    }

    //VERIFICA SE O TOKEN ESTÁ NO FORMATO CORRETO (Bearer Token)
    const [bearer, token] = authCabecalho.split(' ');

    if (bearer !== 'Bearer' || !token) {
        return res.status(401).json({ error: "Formato de token inválido'." });
    }

    //VERIFICA SE O O TOKEN EXISTE
    if(!token){
        return res.status(401).json({error: "Token não fornecido"})
    }

    //VERIFICA E DECODIFICA O TOKEN
    try{
        const decodificado =jwt.verify(token, SECRET_KEY);
        req.user=decodificado; //ADICIONA O USUARIO DECODIFICADO A REQUISIÇÃO
        next(); //PASSAR PARA PROXIMA ROTA(MIDDLEWARE)
    }catch (error)
    {
        return res.status(401).json({error: "Falha na autenticação do Token"})
    }
};


//RENOVA O TOKEN 

app.post('/renovatoken', async (req,res)=>{

    const {tokenRenovado} = req.body;

    //VERIFICA SE O TOKEN DE ATUALIZAÇÃO FOI FORNECIDO
    if(!tokenRenovado){ 
        return res.status(401).json({error:"Nenhum Token de atualização fornecido"});
    }

    try {
        //VERIFICA E DECODIFICA O TOKEN DE ATUALIZAÇÃO
        const decodificado =jwt.verify(tokenRenovado, REFRESH_SECRET_KEY);

        //LÊ O ARQUIVO USUARIOS
        const userData = JSON.parse(await fs.readFile(Usuarios_File,'utf-8'));

        //PROCURA O USUARIO PELO ID DECODIFICADO
        const user= userData.find(u => u.id === decodificado.userId);

        if(!user){
            return res.status(401).json({error:"Usuário não encontrado"})
        }

        //GERAR UM NOVO TOKEN DE ACESSO
        const novoToken = jwt.sign({userId:user.id, username: user.username}, SECRET_KEY, { expiresIn: '15m'});

        //RETORNA O NOVO TOKEN
        res.json({ token:novoToken });

    }catch(error){
        console.log("erro ao renovar o token", error);
        return res.status(500).json({ error: 'Erro interno ao renovar o token.'});
    }

});



/********************************************************************************************************/
//                                               ROTA LOGIN                                             //
/********************************************************************************************************/
app.post('/', async(req,res)=>{
    //PEGA O USUARIO E A SENHA DIGITADOS NO CORPO DA PÁGINA
    const  {username, password }=req.body;

    try{
        //LÊ O ARQUIVO USUARIOS, E O AWAIT PAUSA  EXECUÇÃO ENQUANTO O ARQUIVO É LIDO
        const userData1 = JSON.parse(await fs.readFile(Usuarios_File,'utf-8'));
        //PESQUISA NO ARQUIVO(BANDO DE DADOS) O PRIMEIRO OBJETO COM USERNAME 
        const user =userData1.find(u => u.username === username);

        if(!user || !(await bcrypt.compare(password, user.password))){
            return res.status(401).json({ error: "usuario e senha inválidos"})
        }
        //SE AUTENTICAÇÃO FOR REALIZADA COM SUCESSO, VAI GERAR UM TOKEN ,E O TEMPO DO TOKEN É DE 15 MINUTOS
        const token =jwt.sign({userId: user.id, username}, SECRET_KEY, {expiresIn: '15m' });
        //O TOKEN RENOVADDO SEM QUE O USUARIO FAÇA LOGIN NOVAMENTE, E O TEMPO EXPIRAÇÃO É 7 DIAS
        const tokenRenovado = jwt.sign({userId: user.id}, REFRESH_SECRET_KEY,{expiresIn:'7d'});

        //RETORNO OS TOKENS E OS DADOS DO USUARIO
        res.json({
            token,
            tokenRenovado,
            user: {
                id: user.id,
                username: user.username,
            }
        })


    }catch(error){
        return res.status(500).json({ error: "Erro ao logar"})
    }
});


/********************************************************************************************************/
//                                          ROTA  CADASTRAR NOVO USUARIO                                //
/********************************************************************************************************/
app.post('/cadastro', async (req, res)=>{
    //Pega o username e password do corpo da solicitação.
  const {username, password} = req.body;

  try{
      //lê os dados do usuário de um arquivo  o await pausa a execução até que o arquivo seja lido
     const userData = JSON.parse(await fs.readFile(Usuarios_File,'utf8'));
     console.log("Arquivo Usuarios_File lido com sucesso:", userData);

     //verifica se o usuario ja existe no banco
     if(userData.find(user =>user.username === username)){
         return res.status(400).json({error: "Usuário ja existe "})
     }
     //realiza o hash da senha do usuario  password: Esta é a senha em texto simples  10: O número de rodadas controla o processo de hash. Um número maior significa mais segurança 
     // (é mais difícil quebrar o hash), mas também leva mais tempo para gerar o hash. 10 é um valor comum e razoável.
     const hashedSenha = await bcrypt.hash(password, 10);
     //  Cria um novo objeto de usuário com timestamp atual
     const novoUsuario = {id:Date.now(),username,password:hashedSenha};

     // puxa o novo usuario e guarda no arquivo  Usuarios_File
     userData.push(novoUsuario);
     await fs.writeFile(Usuarios_File,JSON.stringify(userData,null,2))
     res.status(201).json({mesage: "Usuario criado com sucesso"})

  }
  catch(error){
     console.error("Erro ao cadastrar o usuario:", error);
     res.status(500).json({error: "Erro ao cadastrar o usuario "})

  }

});

/********************************************************************************************************/
//                                   ROTA  CADASTRAR LIVROS                                             //
/********************************************************************************************************/
app.post('/livros',verificaToken, async(req,res)=>{

    const {titulo,resumo,ano,paginas,isbn}= req.body;

    try{
        //lendo os dados do arquivo e esperando até que o arquivo seja lido
        const dadosLivros = JSON.parse(await fs.readFile(Livros_File,'utf-8'));
        
        //Objeto novoLivro 
        const novoLivro ={
            id:Date.now(),
            titulo,
            resumo,
            ano,
            paginas:Number(paginas),
            isbn:Number(isbn),
        };
        //recebe o novo livro e adiciona no arquivo Livros_File
        dadosLivros.push(novoLivro);
        await fs.writeFile(Livros_File, JSON.stringify(dadosLivros,null,2))

        res.status(201).json(novoLivro);

    }catch(error){
        res.status(500).json({error: "Erro ao cadastrar Livro"})
    }

});




/********************************************************************************************************/
//                                 ROTA PARA BUSCAR TODOS OS LIVROS CADASTRADO                          //
/********************************************************************************************************/
app.get('/livros',verificaToken, async(req,res)=>{
    try{
        const dadosLivros = JSON.parse(await fs.readFile(Livros_File,'utf-8'));
        res.json(dadosLivros);
    }catch(error){
        res.status(500).json({error: "Erro ao Buscar Livro"});
    }
});


/********************************************************************************************************/
//                                 ROTA PARA PESQUISAR UM LIVRO ESPECIFICO                              //
/********************************************************************************************************/

app.get('/livros/:id',verificaToken, async (req, res) => {
    const { id } = req.params;
    
    try {
        const DadosLivros = JSON.parse(await fs.readFile(Livros_File, 'utf8'));
        const livro = DadosLivros.find(livro => livro.id === parseInt(id));
        
        if (!livro) {
            return res.status(404).json({ error: 'Livro não encontrado' });
        }
        
        res.json(livro);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar o livro' });
    }
});

/********************************************************************************************************/
//                                 ROTA PARA EDITAR O LIVRO                                             //
/********************************************************************************************************/
app.put('/livros/:id',verificaToken, async (req, res) => {
    
    //recebe o id para realizar a alteração
    const { id } = req.params;
    const { titulo,resumo, ano, paginas, isbn } = req.body;
    
    try {
        const dadosLivros = JSON.parse(await fs.readFile(Livros_File, 'utf8'));
        const livroIndex = dadosLivros.findIndex(livro => livro.id === parseInt(id));
        
        if (livroIndex === -1) {
            return res.status(404).json({ error: 'Livro não encontrado' });
        }
        
        //busca tudo que já esta cadastrado e adiciona a nova alteração (spred)
        const updatedLivro = {
            ...dadosLivros[livroIndex],
            titulo,
            resumo,
            ano,
            paginas: Number(paginas),
            isbn,
        };
        
        dadosLivros[livroIndex] = updatedLivro;
        await fs.writeFile(Livros_File, JSON.stringify(dadosLivros, null, 2));
        
        res.json(updatedLivro);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar o livro' });
    }
});

/********************************************************************************************************/
//                                 ROTA PARA EXCLUIR UM LIVRO                                            //
/********************************************************************************************************/
app.delete('/livros/:id',verificaToken, async (req, res) => {

    //recebe o id para realizar a exclusão
   const { id } = req.params;
   
   try {
       const dadosLivros = JSON.parse(await fs.readFile(Livros_File, 'utf8'));
       const filtroLivro = dadosLivros.filter(livro => livro.id !== parseInt(id));
       
       if (filtroLivro.length === dadosLivros.length) {
           return res.status(404).json({ error: 'Livro não encontrado' });
       }
       
       await fs.writeFile(Livros_File, JSON.stringify(filtroLivro, null, 2));
       
       res.json({ message: 'Livro excluído com sucesso' });
   } catch (error) {
       res.status(500).json({ error: 'Erro ao excluir livro' });
   }
});


/********************************************************************************************************/
//                                 ROTA CADASTRAR AUTORES                                               //
/********************************************************************************************************/

app.post('/autores',verificaToken, async (req, res) => {
    const { nome, email,telefone,bio } = req.body;
    
    try {
        const dadosAutores = JSON.parse(await fs.readFile(Autores_File, 'utf8'));
        
        const novoAutor = {
            id: Date.now(),
            nome,
            email,
            telefone,
            bio,
        };
        
        dadosAutores.push(novoAutor);
        await fs.writeFile(Autores_File, JSON.stringify(dadosAutores, null, 2));
        
        res.status(201).json(novoAutor);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao criar Autor' });
    }
});

/********************************************************************************************************/
//                                ROTA PARA BUSCAR TODOS OS AUTORES CADASTRADOS                         //
/********************************************************************************************************/

app.get('/autores',verificaToken, async (req, res) => {
    try {
        const dadosAutores = JSON.parse(await fs.readFile(Autores_File, 'utf8'));
        res.json(dadosAutores);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar Autores' });
    }
});


/********************************************************************************************************/
//                                ROTA PARA PESQUISAR UM AUTOR ESPECIFICO                               //
/********************************************************************************************************/

app.get('/autores/:id',verificaToken, async (req, res) => {
    const { id } = req.params;
    
    try {
        const dadosAutores = JSON.parse(await fs.readFile(Autores_File, 'utf8'));
        const autor = dadosAutores.find(autor => autor.id === parseInt(id));
        
        if (!autor) {
            return res.status(404).json({ error: 'Autor não encontrado' });
        }
        
        res.json(autor);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar o autor' });
    }
});

/********************************************************************************************************/
//                                ROTA PARA EDITAR AUTORES                                              //
/********************************************************************************************************/

app.put('/autores/:id',verificaToken, async (req, res) => {
    const { id } = req.params;
    const { nome, email,telefone,bio }= req.body;
    
    try {
        const dadosAutores = JSON.parse(await fs.readFile(Autores_File, 'utf8'));
        const autoresIndex = dadosAutores.findIndex(autor => autor.id === parseInt(id));
        
        if (autoresIndex === -1) {
            return res.status(404).json({ error: 'Autor não encontrado' });
        }
        
        const updatedAutor = {...dadosAutores[autoresIndex],
            nome,
            email,
            telefone,
            bio,
        };
        
        dadosAutores[autoresIndex] = updatedAutor;
        //o numero 2 é o espaço para identamento no arquivo json
        await fs.writeFile(Autores_File, JSON.stringify(dadosAutores, null, 2));
        
        res.json(updatedAutor);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar o Autor' });
    }
});

/********************************************************************************************************/
//                                ROTA PARA EXCLUIR AUTORES                                              //
/********************************************************************************************************/

app.delete('/autores/:id',verificaToken, async (req, res) => {
    const { id } = req.params;
    
    try {
        const dadosAutores = JSON.parse(await fs.readFile(Autores_File, 'utf8'));
        const filtroAutor = dadosAutores.filter(autor => autor.id !== parseInt(id));
        
        if (filtroAutor.length === dadosAutores.length) {
            return res.status(404).json({ error: 'Autor não encontrado' });
        }
        
        await fs.writeFile(Autores_File, JSON.stringify(filtroAutor, null, 2));
        
        res.json({ message: 'Autor excluído com sucesso' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao excluir Autor' });
    }
});


/********************************************************************************************************/
//                                ROTA PARA CADASTRAR CATEGORIAS                                        //
/********************************************************************************************************/

app.post('/categorias',verificaToken, async (req, res) => {
    const { nome } = req.body;
    
    try {
        const dadosCategorias = JSON.parse(await fs.readFile(Categorias_File, 'utf8'));
        
        const novoCategoria = {
            id: Date.now(),
            nome,
        };
        
        dadosCategorias.push(novoCategoria);
        await fs.writeFile(Categorias_File, JSON.stringify(dadosCategorias, null, 2));
        
        res.status(201).json(novoCategoria);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao criar Categoria' });
    }
});

/********************************************************************************************************/
//                                ROTA PARA BUSCAR TODOS OS CATEGORIAS CADASTRADOS                      //
/********************************************************************************************************/

app.get('/categorias',verificaToken, async (req, res) => {
    try {
        const dadosCategorias = JSON.parse(await fs.readFile(Categorias_File, 'utf8'));
        res.json(dadosCategorias);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar Categorias' });
    }
});

/********************************************************************************************************/
//                                ROTA PARA PESQUISAR UMA CATEGORIAS ESPECIFICA                         //
/********************************************************************************************************/

app.get('/categorias/:id',verificaToken, async (req, res) => {
    const { id } = req.params;
    
    try {
        const dadosCategorias = JSON.parse(await fs.readFile(Categorias_File, 'utf8'));
        const categoria = dadosCategorias.find(categoria => categoria.id === parseInt(id));
        
        if (!categoria) {
            return res.status(404).json({ error: 'Categoria não encontrado' });
        }
        
        res.json(categoria);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar o Categoria' });
    }
});

/********************************************************************************************************/
//                                    ROTA PARA EDITAR CATEGORIAS                                       //
/********************************************************************************************************/

app.put('/categorias/:id',verificaToken, async (req, res) => {
    const { id } = req.params;
    const { nome }= req.body;
    
    try {
        const dadosCategorias = JSON.parse(await fs.readFile(Categorias_File, 'utf8'));
        const categoriasIndex = dadosCategorias.findIndex(categoria => categoria.id === parseInt(id));
        
        if (categoriasIndex === -1) {
            return res.status(404).json({ error: 'Categoria não encontrado' });
        }
        
        const updatedCategoria = {...dadosCategorias[categoriasIndex],
            nome,
        };
        
        dadosCategorias[categoriasIndex] = updatedCategoria;
        //o numero 2 é o espaço para identamento no arquivo json
        await fs.writeFile(Categorias_File, JSON.stringify(dadosCategorias, null, 2));
        
        res.json(updatedCategoria);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar o Categoria' });
    }
});

/********************************************************************************************************/
//                                    ROTA  PARA EXCLUIR CATEGORIAS                                     //
/********************************************************************************************************/


app.delete('/categorias/:id',verificaToken, async (req, res) => {
    const { id } = req.params;
    
    try {
        const dadosCategorias = JSON.parse(await fs.readFile(Categorias_File, 'utf8'));
        const filtroCategoria = dadosCategorias.filter(categoria => categoria.id !== parseInt(id));
        
        if (filtroCategoria.length === dadosCategorias.length) {
            return res.status(404).json({ error: 'Categoria não encontrada' });
        }
        
        await fs.writeFile(Categorias_File, JSON.stringify(filtroCategoria, null, 2));
        
        res.json({ message: 'Categoria excluído com sucesso' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao excluir Categoria' });
    }
});


/********************************************************************************************************/
//                                    ROTA  PARA CADASTRAR EDITORAS                                     //
/********************************************************************************************************/

app.post('/editoras',verificaToken, async (req, res) => {
    const { nome,telefone, endereco } = req.body;
    
    try {
        const dadosEditoras = JSON.parse(await fs.readFile(Editoras_File, 'utf8'));
        
        const novaEditora = {
            id: Date.now(),
            nome,
            telefone,
            endereco,
        };
        
        dadosEditoras.push(novaEditora);
        await fs.writeFile(Editoras_File, JSON.stringify(dadosEditoras, null, 2));
        
        res.status(201).json(novaEditora);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao criar Editora' });
    }
});

/********************************************************************************************************/
//                                    ROTA  PARA BUSCAR TODOS OS EDITORAS CADASTRADOS                   //
/********************************************************************************************************/

app.get('/editoras',verificaToken, async (req, res) => {
    try {
        const dadosEditoras = JSON.parse(await fs.readFile(Editoras_File, 'utf8'));
        res.json(dadosEditoras);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar Editoras' });
    }
});


/********************************************************************************************************/
//                                    ROTA  PARA PESQUISAR UMA EDITORA ESPECIFICA                       //
/********************************************************************************************************/

app.get('/editoras/:id',verificaToken, async (req, res) => {
    const { id } = req.params;
    
    try {
        const dadosEditoras = JSON.parse(await fs.readFile(Editoras_File, 'utf8'));
        const editora = dadosEditoras.find(editora => editora.id === parseInt(id));
        
        if (!editora) {
            return res.status(404).json({ error: 'Editora não encontrada' });
        }
        
        res.json(editora);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar a Editora' });
    }
});

/********************************************************************************************************/
//                                    ROTA PARA EDITAR EDITORAS                                         //
/********************************************************************************************************/

app.put('/editoras/:id',verificaToken, async (req, res) => {
    const { id } = req.params;
    const { nome,telefone,endereco }= req.body;
    
    try {
        const dadosEditoras = JSON.parse(await fs.readFile(Editoras_File, 'utf8'));
        const editoraIndex = dadosEditoras.findIndex(editora => editora.id === parseInt(id));
        
        if (editoraIndex === -1) {
            return res.status(404).json({ error: 'Editora não encontrado' });
        }
        
        const updatedEditora = {...dadosEditoras[editoraIndex],
            nome,
            telefone,
            endereco,
        };
        
        dadosEditoras[editoraIndex] = updatedEditora;
        //o numero 2 é o espaço para identamento no arquivo json
        await fs.writeFile(Editoras_File, JSON.stringify(dadosEditoras, null, 2));
        
        res.json(updatedEditora);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar Editora' });
    }
});


/********************************************************************************************************/
//                                    ROTA PARA EXCLUIR EDITORAS                                         //
/********************************************************************************************************/

app.delete('/editoras/:id',verificaToken, async (req, res) => {
    const { id } = req.params;
    
    try {
        const dadosEditoras = JSON.parse(await fs.readFile(Editoras_File, 'utf8'));
        const filtroEditora = dadosEditoras.filter(editora => editora.id !== parseInt(id));
        
        if (filtroEditora.length === dadosEditoras.length) {
            return res.status(404).json({ error: 'Editora não encontrada' });
        }
        
        await fs.writeFile(Editoras_File, JSON.stringify(filtroEditora, null, 2));
        
        res.json({ message: 'Editora excluído com sucesso' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao excluir Editora' });
    }
});


//EXECUTA O SERVIDOR NA PORTA 3000
const porta =3000;
app.listen(porta,()=>{
    console.log(`Servidor Rodando na porta ${porta}`)
})