use casbin::Result;
use casbin::{CoreApi, Enforcer};
use casbin_rbatis_adapter::CasbinRbatisAdapter;
use rbatis::Rbatis;
use rbdc_mysql::driver::MysqlDriver;

#[tokio::main]
async fn main() -> Result<()> {
    println!(r#"mysql_sample"#);
    let rb = Rbatis::new();

    // 创建rbatis 实例
    rb.init(
        MysqlDriver {},
        "mysql://casbin:Git785230@mysql-internet-cn-east-2-b5cfacbdb6a34fad.rds.jdcloud.com:3306/casbin",
    )
    .unwrap();
    rb.get_pool().unwrap().resize(10);

    // RB.init(DatabaseDriver {}, database_url).eOk(xpect("[abs_admin] rbatis pool init fail!");

    let rb_casbin = CasbinRbatisAdapter::new(rb.clone(), true).await?;

    let e = Enforcer::new("examples/rbac_model.conf", rb_casbin).await?;

    let sub = "alice"; // the user that wants to access a resource.
    let obj = "data1"; // the resource that is going to be accessed.
    let act = "read"; // the operation that the user performs on the resource.

    if let Ok(authorized) = e.enforce((sub, obj, act)) {
        if authorized {
            // permit alice to read data1
            println!("pass")
        } else {
            // deny the request
            println!("deny")
        }
    } else {
        // error occurs
        println!("error occurs")
    }

    Ok(())
}
