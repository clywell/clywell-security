namespace Clywell.Core.Security.Tests.Unit;

public class HasPermissionAttributeTests
{
    [Fact]
    public void Constructor_SetsPolicyWithPermissionPrefix()
    {
        var attribute = new HasPermissionAttribute("articles.edit");

        Assert.Equal("Permission:articles.edit", attribute.Policy);
    }

    [Fact]
    public void Constructor_DifferentPermissions_ProduceDifferentPolicies()
    {
        var attr1 = new HasPermissionAttribute("articles.edit");
        var attr2 = new HasPermissionAttribute("articles.delete");

        Assert.NotEqual(attr1.Policy, attr2.Policy);
    }

    [Fact]
    public void Attribute_AllowsMultipleOnSameTarget()
    {
        var attributeUsage = typeof(HasPermissionAttribute)
            .GetCustomAttributes(typeof(AttributeUsageAttribute), false)
            .Cast<AttributeUsageAttribute>()
            .Single();

        Assert.True(attributeUsage.AllowMultiple);
    }
}
