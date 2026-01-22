package com.trackwize.authentication.mapper;

import com.trackwize.authentication.model.entity.User;
import com.trackwize.authentication.provider.UserProvider;
import org.apache.ibatis.annotations.*;

import java.util.List;

@Mapper
public interface UserMapper {

    @SelectProvider(type = UserProvider.class, method = "findAll")
    @Results(id = "userMap", value = {
            @Result(property = "userId", column = "user_id"),
            @Result(property = "email", column = "email"),
            @Result(property = "password", column = "password"),
            @Result(property = "contactNumber", column = "contact_number"),
            @Result(property = "name", column = "name"),
            @Result(property = "status", column = "status"),
            @Result(property = "createdBy", column = "created_by"),
            @Result(property = "createdDate", column = "created_date"),
            @Result(property = "updatedBy", column = "updated_by"),
            @Result(property = "updatedDate", column = "updated_date")
    })
    List<User> findAll();

    @SelectProvider(type = UserProvider.class, method = "findByEmail")
    @ResultMap("userMap")
    User findByEmail(String email);

    @SelectProvider(type = UserProvider.class, method = "findById")
    @ResultMap("userMap")
    User findById(Long userId);

    @UpdateProvider(type = UserProvider.class, method = "updatePassword")
    int updatePassword(User user);

    @InsertProvider(type = UserProvider.class, method = "create")
    int create(User user);

    @UpdateProvider(type = UserProvider.class, method = "updateRecordStatus")
    int updateRecordStatus(
            @Param("email") String email,
            @Param("status") String status
    );

    @SelectProvider(type = UserProvider.class, method = "existsByEmail")
    boolean existsByEmail(String email);
}
