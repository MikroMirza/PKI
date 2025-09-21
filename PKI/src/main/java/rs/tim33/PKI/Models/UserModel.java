package rs.tim33.PKI.Models;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
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
    private String email;
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    private Role role; // ADMIN, CA, USER

    //Only for regular users
    @OneToMany(mappedBy = "ownerUser")
    private List<CertificateModel> certificates = new ArrayList<>();
    private String privateOrganisation;
    @Lob
    private byte[] keystorePasswordEncrypted;
    private boolean isVerified=false;
}
