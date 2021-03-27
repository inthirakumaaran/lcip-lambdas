package app.management.manager;

import com.google.gson.JsonObject;

import app.management.dao.UpdateDB;
import app.management.exception.DBException;
import app.management.model.config.Configuration;
import app.management.model.entity.UserDataEntity;

import javax.persistence.PersistenceException;

public class UserManager {

    private final Configuration config;
    private final UpdateDB updateDB;

    public UserManager(Configuration config) {

        this.config = config;
        this.updateDB = null;

    }

    public UserManager(UpdateDB updateDB, Configuration config) {

        this.config = config;
        this.updateDB = updateDB;

    }

    private JsonObject createOutput(boolean isSuccess, String message) {

        JsonObject output = new JsonObject();
        output.addProperty("status", isSuccess ? "added" : "failed");
        return output;
    }

    public JsonObject addUser(UserDataEntity userData) throws DBException, Exception {
        // Avoid creating duplicate keys
        String username = userData.getUsername();

        if (username == null || username.isEmpty()) {
            throw new Exception("User name cannot be empty");
        }
        persistToDB(userData);
        return createOutput(true, null);
    }

    public JsonObject deletUser(String  name, int id) throws DBException, Exception {

        removeFromDB(name, id);
        return createOutput(true, null);
    }

    private synchronized void removeFromDB(String name, int id) throws DBException {

        int numAttempts = 0;
        do {
            ++numAttempts;
            try {
                updateDB.removeEntity(name, id);
                return;
            } catch (PersistenceException e) {
                Throwable cause = e.getCause();
//                if ((cause instanceof CommunicationsException || cause instanceof JDBCConnectionException)) {
//                    continue;
//                }
                throw new RuntimeException(
                        "Exception occurred when creating EntityManagerFactory for the named " + "persistence unit: ",
                        e);
            }
        } while (numAttempts <= config.getDatabaseConfig().getMaxRetries());
    }


    private synchronized void persistToDB(UserDataEntity userData) throws DBException {

        int numAttempts = 0;
        do {
            ++numAttempts;
            try {
                updateDB.insertEntity(userData);
                return;
            } catch (PersistenceException e) {
                Throwable cause = e.getCause();
//                if ((cause instanceof CommunicationsException || cause instanceof JDBCConnectionException)) {
//                    continue;
//                }
                throw new RuntimeException(
                        "Exception occurred when creating EntityManagerFactory for the named " + "persistence unit: ",
                        e);
            }
        } while (numAttempts <= config.getDatabaseConfig().getMaxRetries());
    }


}
