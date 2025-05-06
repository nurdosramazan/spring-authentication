package kz.nurdos.spring_security.models;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import kz.nurdos.spring_security.models.enums.RoleType;

@Entity
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long roleId;
    private RoleType roleName;

    public RoleType getRoleName() {
        return roleName;
    }
}
