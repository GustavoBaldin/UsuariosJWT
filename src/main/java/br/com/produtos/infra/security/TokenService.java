package br.com.produtos.infra.security;

import br.com.produtos.model.user.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;


@Service
public class TokenService {

    //Construtor com "User user" porque precisamos usar ele pra inserir no token, atrelar o token a um usuário
    public String gerarToken(User user) {
        //Uma data de 2 horas a partir da criação só pra testar
        Instant dataExpiracao = LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));

        /*
        Cria o token, esse código é padrão CTRL C CTRL V, com vários "." alguma coisa que podemos adicionar,
        incluindo o usuário com o .withSubject()
         */
        try {
            Algorithm algorithm = Algorithm.HMAC256("secretuser");
            return JWT.create()
                    .withIssuer("User Login")
                    .withSubject(user.getUsername())
                    .withExpiresAt(dataExpiracao)
                    .sign(algorithm);
        } catch (JWTCreationException exception){
            throw new RuntimeException("O token deu erro");

        }
    }

    //O método capta a String de um header qualquer (Mobile ou Web) através do HttpServletRequest request)
    public String recuperarToken(HttpServletRequest request) {
        var authorization = request.getHeader("Authorization");
        if (authorization != null) {
            return authorization.replace("Bearer ", "");
        }

        return null;
    }

    public String validarToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256("secretuser");
            return JWT.require(algorithm)
                    .withIssuer("User Login")
                    .build()
                    .verify(token)
                    .getSubject();

        } catch (JWTVerificationException exception){
            throw new RuntimeException("Alguma informação no seu token tá errada");
        }
    }
}
