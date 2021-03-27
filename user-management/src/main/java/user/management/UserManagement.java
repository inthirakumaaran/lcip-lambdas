package user.management;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.google.gson.JsonObject;
import user.management.dao.UpdateDB;
import user.management.manager.UserManager;
import user.management.model.UserData;
import user.management.model.config.Configuration;
import user.management.model.entity.UserDataEntity;
import user.management.utils.Constants;
import user.management.utils.Utils;

import java.util.HashMap;
import java.util.Map;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

public class UserManagement {

    private static Configuration config = Utils.loadConfig(Constants.Configurations.CONFIGURATION_YAML,
                                                           Configuration.class);

    private static UpdateDB updateDB;

    static {
        Map<String, Object> jdbcConfig = new HashMap<>();
        if (config.getDatabaseConfig().getEndpoint() != null) {
            jdbcConfig.put(Constants.Database.JDBC_URL, config.getDatabaseConfig().getEndpoint());
        }
        if (config.getDatabaseConfig().getCredentials().getUsername() != null) {
            jdbcConfig.put(Constants.Database.JDBC_USER, config.getDatabaseConfig().getCredentials().getUsername());
        }
        if (config.getDatabaseConfig().getCredentials().getPassword() != null) {
            jdbcConfig.put(Constants.Database.JDBC_PASSWORD, config.getDatabaseConfig().getCredentials().getPassword());
        }
        if (config.getDatabaseConfig().getPoolSize() != null) {
            jdbcConfig.put(Constants.Database.C3P0_MAX_CONNECTION_POOL_SIZE, config.getDatabaseConfig().getPoolSize());
        }

        EntityManagerFactory emf = Persistence.createEntityManagerFactory(Constants.Database.PERSISTENCE_UNIT_NAME,
                                                                          jdbcConfig);
        updateDB = new UpdateDB(emf, 3, 5000);
    }

    protected static UserManager userManager = new UserManager(updateDB, config);

    public static void main(String[] args) {

        //addUser();
        // removeUser("niro" , 1234);
    }

    //
    //    private Object addUser(UserDataEntity userData, Context context) {
    //        LambdaLogger logger = context.getLogger();
    //        String okResult = "200 OK";
    //        // log execution details
    //        logger.log("initializing hanlder ");
    //
    //        //         config = Utils.loadConfig(Constants.Configurations.CONFIGURATION_YAML, Configuration.class);
    //
    //        JsonObject response = new JsonObject();
    //        try {
    //            response = userManager.addUser(userData);
    //        } catch (Exception e) {
    //            logger.log("Exception :: " + e);
    //            e.printStackTrace();
    //        }
    //        // logger.log("Response : " + response.toString());
    //        return response.toString();
    //    }

}