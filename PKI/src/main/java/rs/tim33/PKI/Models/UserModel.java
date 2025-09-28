package rs.tim33.PKI.Models;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class UserModel {
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String surname;
    @Column(unique = true)
    private String email;
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    private Role role; // ADMIN, CA, USER

    //Only for CA users
    //Contains the CA certificates that are available to this user
    //The admin decides which CA certificates are available to which CA users
    @OneToMany
    private Set<CertificateModel> certificates = new HashSet<>();
    
    
    //Only for regular users
    private String organization;
    @Column(columnDefinition = "TEXT")
    private String keystorePasswordEncrypted;
    private boolean isVerified=false;
}
