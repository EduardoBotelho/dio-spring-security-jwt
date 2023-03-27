package dio.diospringsecurityjwt.controller;

import dio.diospringsecurityjwt.dto.Login;
import dio.diospringsecurityjwt.dto.Sessao;
import dio.diospringsecurityjwt.model.User;
import dio.diospringsecurityjwt.repository.UserRepository;
import dio.diospringsecurityjwt.security.JWTCreator;
import dio.diospringsecurityjwt.security.JWTObject;
import dio.diospringsecurityjwt.security.SecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import javax.xml.crypto.Data;
import java.util.Date;

public class LoginController {
    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private SecurityConfig securityConfig;
    @Autowired
    private UserRepository repository;

    @PostMapping("/login")
    public Sessao logar(@RequestBody Login login){
        User user = repository.findByUsername(login.getUsername());
        if(user != null){
            boolean passwordOk = encoder.matches(login.getPassword(), user.getPassword());
            if(!passwordOk){
                throw new RuntimeException("Senha invalida para o Login:"+ login.getUsername());
            }
            Sessao sessao = new Sessao();
            sessao.setLogin(user.getUsername());

            JWTObject  jwtObject = new JWTObject();
            jwtObject.setIssuedAt(new Date(System.currentTimeMillis()));
            jwtObject.setExpiration(new Date(System.currentTimeMillis() + SecurityConfig.EXPIRATION));
            jwtObject.setRoles(user.getRoles());
            sessao.setToken(JWTCreator.create(SecurityConfig.PREFIX, SecurityConfig.KEY,jwtObject));
            return sessao;
        }else {
            throw new RuntimeException("Erro ao tentar fazer login!");
        }

    }
}
