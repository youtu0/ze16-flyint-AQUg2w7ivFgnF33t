
书接上回，上一章介绍了Swagger代替品Scalar，在使用中遇到不少问题，今天单独分享一下之前Swagger中常用的功能如何在Scalar中使用。


下面我们将围绕文档版本说明、接口分类、接口描述、参数描述、枚举类型、文件上传、JWT认证等方面详细讲解。


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215310792-2091884480.png)


# ***01***、版本说明


我们先来看看默认添加后是什么样子的。



```
public static void Main(string[] args)
{
    var builder = WebApplication.CreateBuilder(args);
    builder.Services.AddControllers();
    builder.Services.AddOpenApi();
    var app = builder.Build();
    app.MapScalarApiReference();
    app.MapOpenApi();
    app.UseAuthorization();
    app.MapControllers();
    app.Run();
}

```

效果如下：


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215259694-36500221.png)


我们可以直接修改builder.Services.AddOpenApi()这行代码，修改这块描述，代码如下：



```
builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((document, context, cancellationToken) =>
    {
        document.Info = new()
        {
            Title = "订单微服务",
            Version = "v1",
            Description = "订单相关接口"
        };
        return Task.CompletedTask;
    });
});

```

我们再来看看效果。


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215252166-815721572.png)


# ***02***、接口分类


通过上图可以看到菜单左侧排列着所有接口，现在我们可以通过Tags特性对接口进行分类，如下图我们把增删改查4个方法分为幂等接口和非幂等接口两类，如下图：


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215244965-1473697518.png)


然后我们看看效果，如下图：


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215238097-1523454009.png)


# ***03***、接口描述


之前使用Swagger我们都是通过生成的注释XML来生成相关接口描述，现在则是通过编码的方式设置元数据来生成相关描述。


可以通过EndpointSummary设置接口摘要，摘要不设置默认为接口url，通过EndpointDescription设置接口描述，代码如下：



```
//获取
[HttpGet(Name = "")]
[Tags("幂等接口")]
[EndpointDescription("获取订单列表")]
public IEnumerable Get()
{
    return null;
}
//删除
[HttpDelete(Name = "{id}")]
[Tags("幂等接口")]
[EndpointSummary("删除订单")]
[EndpointDescription("根据订单id，删除相应订单")]
public bool Delete(string id)
{
    return true;
}

```

运行效果如下：


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215228980-1534369790.png)


# ***04***、参数描述


同样可以通过Description特性来设置参数的描述，并且此特性可以直接作用于接口中参数之前，同时也支持作用于属性上，可以看看下面示例代码。



```
public class Order
{
    [property: Description("创建日期")]
    public DateOnly Date { get; set; }
    [property: Required]
    [property: DefaultValue(120)]
    [property: Description("订单价格")]
    public int Price { get; set; }
    [property: Description("订单折扣价格")]
    public int PriceF => (int)(Price * 0.5556);
    [property: Description("商品名称")]
    public string? Name { get; set; }
}
[HttpPut(Name = "{id}")]
[Tags("非幂等接口")]
public bool Put([Description("订单Id")] string id, Order order)
{
    return true;
}

```

效果如下图：


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215219274-1709675984.png)


从上图可以发现除了描述还有默认值、必填项、可空等字样，这些是通过其他元数据设置的，对于属性还有以下元数据可以进行设置。


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215211410-705711884.png)


# ***05***、枚举类型


对于枚举类型，我们正常关注两个东西，其一为枚举项以int类型展示还是以字符串展示，其二为枚举项显示描述信息。


关于第一点比较简单只要对枚举类型使用JsonStringEnumConverter即可，代码如下：



```
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum OrderStatus
{
    [Description("等待处理")]
    Pending = 1,
    [Description("处理中")]
    Processing = 2,
    [Description("已发货")]
    Shipped = 3,
    [Description("已送达")]
    Delivered = 4,
}

```

效果如下：


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215202888-361576765.png)


通过上图也可以引发关于第二点的需求，如何对每个枚举项添加描述信息。


要达到这个目标需要做两件事，其一给每个枚举项通过Description添加元数据定义，其二我们要修改文档的数据结构Schema。


修改builder.Services.AddOpenApi()，通过AddSchemaTransformer方法修改文档数据结构，代码如下：



```
options.AddSchemaTransformer((schema, context, cancellationToken) =>
{
    //找出枚举类型
    if (context.JsonTypeInfo.Type.BaseType == typeof(Enum))
    {
        var list = new List();
        //获取枚举项
        foreach (var enumValue in schema.Enum.OfType())
        {
            //把枚举项转为枚举类型
            if (Enum.TryParse(context.JsonTypeInfo.Type, enumValue.Value, out var result))
            {
                //通过枚举扩展方法获取枚举描述
                var description = ((Enum)result).ToDescription();
                //重新组织枚举值展示结构
                list.Add(new OpenApiString($"{enumValue.Value} - {description}"));
            }
            else
            {
                list.Add(enumValue);
            }
        }
        schema.Enum = list;
    }
    return Task.CompletedTask;
});

```

我们再来看看结果。


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215151674-1805099040.png)


但是这也带来了一个问题，就是参数的默认值也是添加描述的格式，显然这样的数据格式作为参数肯定是错误的，因此我们需要自己注意，如下图。目前我也没有发现更好的方式即可以把每项枚举描述加上，又不影响参数默认值，有解决方案的希望可以不吝赐教。


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215141784-283370234.png)


# ***06***、文件上传


下面我们来看看文件上传怎么用，直接上代码：



```
[HttpPost("upload/image")]
[EndpointDescription("图片上传接口")]
[DisableRequestSizeLimit]
public bool UploadImgageAsync(IFormFile file)
{
    return true;
}

```

然后我们测试一下效果。


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215132090-244151203.png)


首先我们可以看到请求示例中相关信息，这个相当于告诉我们后面要怎么选择文件上传，我们继续点击Test Request。


首先请求体需要选择multipart/form\-data，上图请求示例中已经给出提示。


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215122155-1293080534.png)


然后设置key为file，上图请求示例中已经给出提示，然后点击File上传图片，最后点击Send即可。


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215113765-1812342326.png)


# ***07***、JWT认证


最后我们来看看如何使用JWT认证，


首先我们需要注入AddAuthentication及AddJwtBearer，具体代码如下：



```
public class JwtSettingOption
{
    //这个字符数量有要求，不能随便写，否则会报错
    public static string Secret { get; set; } = "123456789qwertyuiopasdfghjklzxcb";
    public static string Issuer { get; set; } = "asdfghjkkl";
    public static string Audience { get; set; } = "zxcvbnm";
    public static int Expires { get; set; } = 120;
    public static string RefreshAudience { get; set; } = "zxcvbnm.2024.refresh";
    public static int RefreshExpires { get; set; } = 10080;
}
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    //取出私钥
    var secretByte = Encoding.UTF8.GetBytes(JwtSettingOption.Secret);
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        //验证发布者
        ValidateIssuer = true,
        ValidIssuer = JwtSettingOption.Issuer,
        //验证接收者
        ValidateAudience = true,
        ValidAudiences = new List<string> { JwtSettingOption.Audience, JwtSettingOption.Audience },
        //验证是否过期
        ValidateLifetime = true,
        //验证私钥
        IssuerSigningKey = new SymmetricSecurityKey(secretByte),
        ClockSkew = TimeSpan.FromHours(1), //过期时间容错值，解决服务器端时间不同步问题（秒）
        RequireExpirationTime = true,
    };
});

```

然后我们需要继续修改builder.Services.AddOpenApi()这行代码，在里面加上如下代码：


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215102031-728622279.png)


其中BearerSecuritySchemeTransformer实现如下：



```
public sealed class BearerSecuritySchemeTransformer(IAuthenticationSchemeProvider authenticationSchemeProvider) : IOpenApiDocumentTransformer
{
    public async Task TransformAsync(OpenApiDocument document, OpenApiDocumentTransformerContext context, CancellationToken cancellationToken)
    {
        var authenticationSchemes = await authenticationSchemeProvider.GetAllSchemesAsync();
        if (authenticationSchemes.Any(authScheme => authScheme.Name == JwtBearerDefaults.AuthenticationScheme))
        {
            var requirements = new Dictionary<string, OpenApiSecurityScheme>
            {
                [JwtBearerDefaults.AuthenticationScheme] = new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.Http,
                    Scheme = JwtBearerDefaults.AuthenticationScheme.ToLower(),
                    In = ParameterLocation.Header,
                    BearerFormat = "Json Web Token"
                }
            };
            document.Components ??= new OpenApiComponents();
            document.Components.SecuritySchemes = requirements;
            foreach (var operation in document.Paths.Values.SelectMany(path => path.Operations))
            {
                operation.Value.Security.Add(new OpenApiSecurityRequirement
                {
                    [new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Id = JwtBearerDefaults.AuthenticationScheme,
                            Type = ReferenceType.SecurityScheme
                        }
                    }] = Array.Empty<string>()
                });
            }
        }
    }
}

```

下面就可以通过\[Authorize]开启接口认证，并实现一个登录接口获取token用来测试。



```
[HttpPost("login")]
[EndpointDescription("登录成功后生成token")]
[AllowAnonymous]
public string  Login()
{
    //登录成功返回一个token
    // 1.定义需要使用到的Claims
    var claims = new[] { new Claim("UserId", "test") };
    // 2.从 appsettings.json 中读取SecretKey
    var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSettingOption.Secret));
    // 3.选择加密算法
    var algorithm = SecurityAlgorithms.HmacSha256;
    // 4.生成Credentials
    var signingCredentials = new SigningCredentials(secretKey, algorithm);
    var now = DateTime.Now;
    var expires = now.AddMinutes(JwtSettingOption.Expires);
    // 5.根据以上，生成token
    var jwtSecurityToken = new JwtSecurityToken(
        JwtSettingOption.Issuer,         //Issuer
        JwtSettingOption.Audience,       //Audience
        claims,                          //Claims,
        now,                             //notBefore
        expires,                         //expires
        signingCredentials               //Credentials
    );
    // 6.将token变为string
    var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
    return token;
}

```

下面我们先用登录接口获取一个token。


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215044619-374608443.png)


我们先用token调用接口，可以发现返回401。


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215034184-222337381.png)


然后我们把上面获取的token放进去，请求成功。


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215026536-1348970944.png)


在这个过程中有可能会遇到一种情况：Auth Type后面的下拉框不可选，如下图。


![](https://img2024.cnblogs.com/blog/386841/202411/386841-20241126215015211-319424695.png)


可能因以下原因导致，缺少\[builder.Services.AddAuthentication().AddJwtBearer();]或\[options.AddDocumentTransformer();]任意一行代码。


***注***：测试方法代码以及示例源码都已经上传至代码库，有兴趣的可以看看。[https://gitee.com/hugogoos/Planner](https://github.com)


 本博客参考[veee加速器](https://blog.liuyunzhuge.com)。转载请注明出处！
