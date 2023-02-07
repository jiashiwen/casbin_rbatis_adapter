# Casbin Rbatis adapter

## Get started

```rust
RB.init(DatabaseDriver {}, database_url).expect("[abs_admin] rbatis pool init fail!");

let rb_casbin = CasbinRbatisAdapter::new(RB.clone(), true).await?;
let mut e = Enforcer::new("acl.conf", rb_casbin).await?;

let sub = "alice"; // the user that wants to access a resource.
let obj = "data1"; // the resource that is going to be accessed.
let act = "read"; // the operation that the user performs on the resource.

if let Ok(authorized) = e.enforce((sub, obj, act)) {
    if authorized {
        // permit alice to read data1
    } else {
        // deny the request
    }
} else {
    // error occurs
}
```

完整示例请参考 examples/mysql_sample.rs