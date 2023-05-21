namespace Identity.Application.Interfaces
{
    public interface IUnitOfWork
    {
        Task CompleteAsync();
    }
}
