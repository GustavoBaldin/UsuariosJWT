package br.com.produtos.controller;

import br.com.produtos.infra.security.TokenService;
import br.com.produtos.model.user.User;
import br.com.produtos.model.user.UserAuthDTO;
import br.com.produtos.model.user.UserRegisterDTO;
import br.com.produtos.repositories.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthenticationManager manager;

    @Autowired
    private TokenService tokenService;


    @PostMapping("/login")
    public ResponseEntity login(@RequestBody @Valid UserAuthDTO dto) {
        var token = new UsernamePasswordAuthenticationToken(dto.login(), dto.password());
        var authentication = manager.authenticate(token);

        var tokenJWT = tokenService.gerarToken((User) authentication.getPrincipal());

        return ResponseEntity.ok(tokenJWT);
    }


    @PostMapping("/register")
    public ResponseEntity register(@RequestBody @Valid UserRegisterDTO data) {
        if(this.userRepository.findByLogin(data.login()) != null) return ResponseEntity.badRequest().build();

        String encryptedPassword = new BCryptPasswordEncoder().encode(data.password());
        User user = new User(data.login(), encryptedPassword);

        this.userRepository.save(user);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/test")
    public ResponseEntity test() {
        return ResponseEntity.ok("Parabéns, você conseguiu");
    }

}
