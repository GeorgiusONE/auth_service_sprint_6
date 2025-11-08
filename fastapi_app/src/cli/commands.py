"""Typer CLI commands for Auth Service management."""

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import selectinload, sessionmaker

from src.core.config import settings
from src.core.security import PasswordHasher, validate_password_strength
from src.models.entity import User, Role, UserRole

# Initialize Typer app
app = typer.Typer(
    name="auth-cli",
    help="Auth Service CLI - Management commands for users, roles, and permissions",
    add_completion=False,
)

# Rich console for pretty output
console = Console()

# Password hasher
pwd_hasher = PasswordHasher()


# Database session helper
async def get_db_session() -> AsyncSession:
    """Create async database session for CLI commands."""
    engine = create_async_engine(
        settings.database_url,
        echo=False,
        pool_pre_ping=True,
    )
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        try:
            yield session
        finally:
            await engine.dispose()


# Helper to run async functions
def run_async(coro):
    """Run async coroutine in sync context."""
    return asyncio.run(coro)


@app.command()
def create_superuser():
    """
    Create a new superuser account.

    Interactively prompts for user details with validation.
    """
    console.print("\n[bold cyan]Create Superuser[/bold cyan]")
    console.print("=" * 50)

    # Get login
    while True:
        login = typer.prompt("Login", type=str)
        if len(login) >= 3:
            break
        console.print("[red]Login must be at least 3 characters long[/red]")

    # Get password
    while True:
        password = typer.prompt("Password", hide_input=True, type=str)
        confirm_password = typer.prompt("Confirm password", hide_input=True, type=str)

        if password != confirm_password:
            console.print("[red]Passwords do not match[/red]")
            continue

        if not validate_password_strength(password):
            console.print(
                "[red]Password is too weak. Requirements:[/red]\n"
                "  - At least 8 characters\n"
                "  - At least one uppercase letter\n"
                "  - At least one lowercase letter\n"
                "  - At least one digit\n"
                "  - At least one special character"
            )
            continue

        break

    # Get names
    first_name = typer.prompt("First name", type=str)
    last_name = typer.prompt("Last name", type=str)

    # Create superuser
    async def _create_superuser():
        async for session in get_db_session():
            # Check if user exists
            result = await session.execute(select(User).where(User.login == login))
            existing_user = result.scalar_one_or_none()

            if existing_user:
                console.print(f"[red]Error: User with login '{login}' already exists[/red]")
                return False

            # Hash password
            hashed_password = pwd_hasher.hash_password(password)

            # Create user
            user = User(
                login=login,
                password=hashed_password,
                first_name=first_name,
                last_name=last_name,
                is_active=True,
                is_superuser=True,
            )

            session.add(user)
            await session.commit()

            console.print(f"\n[green]✓ Superuser '{login}' created successfully![/green]")
            console.print(f"  ID: {user.id}")
            console.print(f"  Login: {user.login}")
            console.print(f"  Name: {user.first_name} {user.last_name}")
            console.print("  Is Superuser: Yes")
            return True

    success = run_async(_create_superuser())
    if not success:
        raise typer.Exit(code=1)


@app.command()
def create_role(
    name: str = typer.Argument(..., help="Unique name for the role"),
    description: Optional[str] = typer.Argument(None, help="Description of the role"),
):
    """
    Create a new role in the system.

    Example:
        python -m src.cli.commands create-role subscriber "Basic subscription access"
    """

    async def _create_role():
        async for session in get_db_session():
            # Check if role exists
            result = await session.execute(select(Role).where(Role.name == name))
            existing_role = result.scalar_one_or_none()

            if existing_role:
                console.print(f"[red]Error: Role with name '{name}' already exists[/red]")
                return False

            # Create role
            role = Role(
                name=name,
                description=description,
            )

            session.add(role)
            await session.commit()

            console.print(f"\n[green]✓ Role '{name}' created successfully![/green]")
            console.print(f"  ID: {role.id}")
            console.print(f"  Name: {role.name}")
            if description:
                console.print(f"  Description: {role.description}")
            return True

    success = run_async(_create_role())
    if not success:
        raise typer.Exit(code=1)


@app.command()
def assign_role(
    user_login: str = typer.Argument(..., help="Login of the user"),
    role_name: str = typer.Argument(..., help="Name of the role to assign"),
):
    """
    Assign a role to a user.

    Example:
        python -m src.cli.commands assign-role john_doe subscriber
    """

    async def _assign_role():
        async for session in get_db_session():
            # Find user
            result = await session.execute(select(User).where(User.login == user_login))
            user = result.scalar_one_or_none()

            if not user:
                console.print(f"[red]Error: User with login '{user_login}' not found[/red]")
                return False

            # Find role
            result = await session.execute(select(Role).where(Role.name == role_name))
            role = result.scalar_one_or_none()

            if not role:
                console.print(f"[red]Error: Role with name '{role_name}' not found[/red]")
                return False

            # Check if already assigned
            result = await session.execute(
                select(UserRole).where(
                    UserRole.user_id == user.id,
                    UserRole.role_id == role.id,
                )
            )
            existing_assignment = result.scalar_one_or_none()

            if existing_assignment:
                console.print(f"[yellow]Warning: User '{user_login}' already has role '{role_name}'[/yellow]")
                return True

            # Assign role
            user_role = UserRole(
                user_id=user.id,
                role_id=role.id,
            )

            session.add(user_role)
            await session.commit()

            console.print(f"\n[green]✓ Role '{role_name}' assigned to user '{user_login}'[/green]")
            return True

    success = run_async(_assign_role())
    if not success:
        raise typer.Exit(code=1)


@app.command()
def list_users(
    with_roles: bool = typer.Option(
        False,
        "--with-roles",
        "-r",
        help="Show roles for each user",
    ),
):
    """
    List all users in the system.

    Example:
        python -m src.cli.commands list-users
        python -m src.cli.commands list-users --with-roles
    """

    async def _list_users():
        async for session in get_db_session():
            # Query users with roles
            result = await session.execute(
                select(User).options(selectinload(User.user_roles).selectinload(UserRole.role))
            )
            users = result.scalars().all()

            if not users:
                console.print("[yellow]No users found[/yellow]")
                return

            # Create table
            table = Table(title=f"\n[bold cyan]Users ({len(users)} total)[/bold cyan]")
            table.add_column("Login", style="cyan", no_wrap=True)
            table.add_column("Name", style="white")
            table.add_column("Is Superuser", style="magenta")

            if with_roles:
                table.add_column("Roles", style="green")
            else:
                table.add_column("Role Count", style="green", justify="center")

            # Add rows
            for user in sorted(users, key=lambda u: u.login):
                roles = [ur.role.name for ur in user.user_roles]

                if with_roles:
                    roles_str = ", ".join(roles) if roles else "-"
                    table.add_row(
                        user.login,
                        f"{user.first_name} {user.last_name}",
                        "Yes" if user.is_superuser else "No",
                        roles_str,
                    )
                else:
                    table.add_row(
                        user.login,
                        f"{user.first_name} {user.last_name}",
                        "Yes" if user.is_superuser else "No",
                        str(len(roles)),
                    )

            console.print(table)

    run_async(_list_users())


@app.command()
def list_roles():
    """
    List all roles in the system with user counts.

    Example:
        python -m src.cli.commands list-roles
    """

    async def _list_roles():
        async for session in get_db_session():
            # Query roles with user_roles
            result = await session.execute(select(Role).options(selectinload(Role.user_roles)))
            roles = result.scalars().all()

            if not roles:
                console.print("[yellow]No roles found[/yellow]")
                return

            # Create table
            table = Table(title=f"\n[bold cyan]Roles ({len(roles)} total)[/bold cyan]")
            table.add_column("Name", style="cyan", no_wrap=True)
            table.add_column("Description", style="white")
            table.add_column("Users", style="green", justify="center")

            # Add rows
            for role in sorted(roles, key=lambda r: r.name):
                user_count = len(role.user_roles)
                description = role.description if role.description else "-"

                table.add_row(
                    role.name,
                    description,
                    str(user_count),
                )

            console.print(table)

    run_async(_list_roles())


if __name__ == "__main__":
    app()
