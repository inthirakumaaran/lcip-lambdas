package app.management.model.entity;

import app.management.utils.Constants;

import java.io.Serializable;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Column;
import javax.persistence.Id;
import javax.persistence.NamedNativeQueries;
import javax.persistence.NamedNativeQuery;

/**
 * Database Entity.
 *
 * @since 1.0.0
 */
@NamedNativeQueries({
        @NamedNativeQuery(
                name = Constants.Database.Queries.FIND_LICENSE_KEY_IF_EXISTS_FOR_A_GIVEN_USER_NAME,
                query = Constants.Database.Queries.FIND_LICENSE_KEY_IF_EXISTS_FOR_A_GIVEN_USER,
                resultClass = UserDataEntity.class
        )
})

@Entity
@Table(name = "USER_INFO")
public class UserDataEntity implements Serializable {

    private static final long serialVersionUID = -4997964964871690908L;


    @Id
    @Column(name = "tenantId")
    private int tenantId;

    @Id
    @Column(name = "username")
    private String username;

    @Column(name = "user_email")
    private String userEmail;



    @Column(name = "password")
    private String password;

    public UserDataEntity() {
    }

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public int getId() {
        return tenantId;
    }

    public void setId(int id) {
        this.tenantId = id;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
